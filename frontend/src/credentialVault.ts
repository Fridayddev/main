import type { SeedPair } from './seedVault'
import { createIsolatedStateContainer, createSafeStorage } from './safeStorage'

const VAULT_STORAGE_KEY = 'harpocrates:credential-vault'
const VAULT_VERSION = 1
const PBKDF2_ITERATIONS = 600000
const DEFAULT_TIMEOUT_MS = 15 * 60 * 1000 // 15 minutes

export interface VaultEnvelope {
  v: number
  salt: string // hex
  iv: string // hex
  ct: string // hex (ciphertext)
}

export type VaultStorage = Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>

export interface CredentialVaultOptions {
  inactivityTimeoutMs?: number
  storage?: VaultStorage
}

export function validateVaultEnvelope(candidate: unknown): VaultEnvelope {
  if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) {
    throw new Error('Vault corrupted: envelope must be an object')
  }

  const record = candidate as Record<string, unknown>

  if (typeof record.v !== 'number' || record.v !== VAULT_VERSION) {
    throw new Error(`Unsupported vault version: ${String(record.v)}`)
  }

  const isHex = (val: unknown): val is string =>
    typeof val === 'string' && val.length > 0 && val.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(val)

  if (!isHex(record.salt)) {
    throw new Error('Unsupported vault parameter: salt must be a non-empty hex string with even length')
  }

  if (!isHex(record.iv)) {
    throw new Error('Unsupported vault parameter: iv must be a non-empty hex string with even length')
  }

  if (!isHex(record.ct)) {
    throw new Error('Unsupported vault parameter: ct must be a non-empty hex string with even length')
  }

  return {
    v: record.v,
    salt: record.salt,
    iv: record.iv,
    ct: record.ct,
  }
}

function bufToHex(buffer: ArrayBuffer): string {
  return [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

function hexToBuf(hex: string): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(Math.ceil(hex.length / 2))
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16)
  }
  return bytes
}

async function deriveKey(password: string, salt: ArrayBuffer): Promise<CryptoKey> {
  const enc = new TextEncoder()
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveBits', 'deriveKey']
  )
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false, // extractable
    ['encrypt', 'decrypt']
  )
}

export class CredentialVault {
  private memoryKey: CryptoKey | null = null
  private seeds: SeedPair | null = null
  private timeoutId: ReturnType<typeof setTimeout> | null = null
  private inactivityTimeoutMs: number
  private storage: VaultStorage

  constructor(
    inactivityTimeoutMsOrOptions?: number | CredentialVaultOptions,
    storage?: VaultStorage
  ) {
    if (typeof inactivityTimeoutMsOrOptions === 'object' && inactivityTimeoutMsOrOptions !== null) {
      this.inactivityTimeoutMs = inactivityTimeoutMsOrOptions.inactivityTimeoutMs ?? DEFAULT_TIMEOUT_MS
      this.storage = inactivityTimeoutMsOrOptions.storage ?? this.getDefaultStorage()
    } else {
      this.inactivityTimeoutMs = inactivityTimeoutMsOrOptions ?? DEFAULT_TIMEOUT_MS
      this.storage = storage ?? this.getDefaultStorage()
    }
  }

  private getDefaultStorage(): VaultStorage {
    if (typeof window !== 'undefined' && window.localStorage) {
      return window.localStorage
    }
    return createIsolatedStateContainer()
  }

  getStorage(): VaultStorage {
    return this.storage
  }

  isLocked(): boolean {
    return this.memoryKey === null || this.seeds === null
  }

  getSeeds(): SeedPair | null {
    this.resetTimeout()
    return this.seeds
  }

  hasVault(): boolean {
    return !!this.storage.getItem(VAULT_STORAGE_KEY)
  }

  async setup(password: string, seeds: SeedPair): Promise<void> {
    const salt = crypto.getRandomValues(new Uint8Array(16))
    const key = await deriveKey(password, salt as unknown as ArrayBuffer)

    const iv = crypto.getRandomValues(new Uint8Array(12))
    const enc = new TextEncoder()
    const pt = enc.encode(JSON.stringify(seeds))

    const ct = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv as unknown as ArrayBuffer,
      },
      key,
      pt
    )

    const envelope: VaultEnvelope = {
      v: VAULT_VERSION,
      salt: bufToHex(salt as unknown as ArrayBuffer),
      iv: bufToHex(iv as unknown as ArrayBuffer),
      ct: bufToHex(ct),
    }

    this.storage.setItem(VAULT_STORAGE_KEY, JSON.stringify(envelope))
    this.memoryKey = key
    this.seeds = { credentialSeed: seeds.credentialSeed, nullifierSeed: seeds.nullifierSeed }
    this.resetTimeout()
  }

  async unlock(password: string): Promise<boolean> {
    const stored = this.storage.getItem(VAULT_STORAGE_KEY)
    if (!stored) throw new Error('Vault is empty')

    let parsed: unknown
    try {
      parsed = JSON.parse(stored)
    } catch {
      throw new Error('Vault corrupted: unable to parse envelope')
    }

    const envelope = validateVaultEnvelope(parsed)

    const salt = hexToBuf(envelope.salt)
    const iv = hexToBuf(envelope.iv)
    const ct = hexToBuf(envelope.ct)

    try {
      const key = await deriveKey(password, salt as unknown as ArrayBuffer)
      const pt = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: iv as unknown as ArrayBuffer,
        },
        key,
        ct as unknown as ArrayBuffer
      )

      const dec = new TextDecoder()
      const seedsRaw = JSON.parse(dec.decode(pt))
      
      this.memoryKey = key
      this.seeds = {
        credentialSeed: seedsRaw.credentialSeed,
        nullifierSeed: seedsRaw.nullifierSeed,
      }
      this.resetTimeout()
      return true
    } catch {
      // Typically an OperationError if decryption fails due to bad password
      return false
    }
  }

  exportVault(): VaultEnvelope {
    const stored = this.storage.getItem(VAULT_STORAGE_KEY)
    if (!stored) {
      throw new Error('Vault is empty')
    }

    let parsed: unknown
    try {
      parsed = JSON.parse(stored)
    } catch {
      throw new Error('Vault corrupted: unable to parse envelope')
    }

    return validateVaultEnvelope(parsed)
  }

  importVault(envelopeOrJson: VaultEnvelope | string): void {
    let parsed: unknown
    if (typeof envelopeOrJson === 'string') {
      try {
        parsed = JSON.parse(envelopeOrJson)
      } catch {
        throw new Error('Vault corrupted: unable to parse envelope')
      }
    } else {
      parsed = envelopeOrJson
    }

    const envelope = validateVaultEnvelope(parsed)
    this.storage.setItem(VAULT_STORAGE_KEY, JSON.stringify(envelope))
    this.lock()
  }

  lock(): void {
    this.memoryKey = null
    // Zero out references
    if (this.seeds) {
      this.seeds.credentialSeed = ''
      this.seeds.nullifierSeed = ''
    }
    this.seeds = null
    this.clearTimeout()
  }

  destroy(): void {
    this.lock()
    this.storage.removeItem(VAULT_STORAGE_KEY)
  }

  async rehearseRecovery(
    options?: VaultRecoveryRehearsalOptions
  ): Promise<VaultRecoveryRehearsalResult> {
    return rehearseVaultRecovery(options)
  }

  private resetTimeout(): void {
    this.clearTimeout()
    if (!this.isLocked() && this.inactivityTimeoutMs > 0) {
      this.timeoutId = setTimeout(() => {
        this.lock()
      }, this.inactivityTimeoutMs)
    }
  }

  private clearTimeout(): void {
    if (this.timeoutId !== null) {
      clearTimeout(this.timeoutId)
      this.timeoutId = null
    }
  }
}

export interface VaultRecoveryRehearsalOptions {
  /** Optional custom synthetic seeds to use for rehearsal. If omitted, random synthetic seeds are generated. */
  syntheticMaterial?: SeedPair
  /** Optional custom passphrase to use for rehearsal. If omitted, a strong synthetic passphrase is used. */
  passphrase?: string
  /** Optional custom isolated container to act as initial source. If omitted, an isolated container is created. */
  isolatedContainer?: VaultStorage
  /** Optional custom isolated container to act as recovery destination. If omitted, an isolated container is created. */
  targetContainer?: VaultStorage
  /** Whether to record completion in safe storage preferences. Defaults to true. */
  markCompleted?: boolean
  /** Storage container for UI preferences if marking completion. Defaults to browser localStorage if available. */
  preferencesStorage?: Storage
}

export interface VaultRecoveryRehearsalResult {
  success: boolean
  syntheticSeedsVerified: boolean
  isolatedExportVerified: boolean
  isolatedImportVerified: boolean
  originalCredentialsUntouched: boolean
  rehearsalCompleted: boolean
  exportedEnvelope: VaultEnvelope
  timestamp: number
}

/**
 * Perform a one-time vault recovery rehearsal with synthetic material in an isolated
 * state container, verifying export and import without touching the user's active private credentials.
 */
export async function rehearseVaultRecovery(
  options?: VaultRecoveryRehearsalOptions
): Promise<VaultRecoveryRehearsalResult> {
  // Capture current state of the user's live storage to verify safety boundary
  const originalLiveStorage = (typeof window !== 'undefined' && window.localStorage)
    ? window.localStorage.getItem(VAULT_STORAGE_KEY)
    : null

  // Guarantee isolated local state containers - NEVER touch user's active private credentials
  const sourceContainer = options?.isolatedContainer ?? createIsolatedStateContainer()
  const targetContainer = options?.targetContainer ?? createIsolatedStateContainer()

  // Generate or use synthetic material
  const syntheticMaterial: SeedPair = options?.syntheticMaterial ?? {
    credentialSeed: `synth_cred_${bufToHex(crypto.getRandomValues(new Uint8Array(16)) as unknown as ArrayBuffer)}`,
    nullifierSeed: `synth_null_${bufToHex(crypto.getRandomValues(new Uint8Array(16)) as unknown as ArrayBuffer)}`,
  }

  const rehearsalPassphrase = options?.passphrase ?? 'SyntheticRehearsal#Vault2026!'

  // 1. Setup the rehearsal vault in the isolated source container
  const sourceVault = new CredentialVault(DEFAULT_TIMEOUT_MS, sourceContainer)
  await sourceVault.setup(rehearsalPassphrase, syntheticMaterial)

  // 2. Verify export through isolated local state container
  const exportedEnvelope = sourceVault.exportVault()
  const serializedExport = JSON.stringify(exportedEnvelope)

  // Fail-closed privacy check: synthetic seeds must never be present in plaintext in the exported envelope
  if (
    serializedExport.includes(syntheticMaterial.credentialSeed) ||
    serializedExport.includes(syntheticMaterial.nullifierSeed)
  ) {
    throw new Error('Recovery rehearsal failed: exported envelope contains unencrypted private witness material')
  }

  const isolatedExportVerified = exportedEnvelope.v === VAULT_VERSION &&
    !!exportedEnvelope.salt &&
    !!exportedEnvelope.iv &&
    !!exportedEnvelope.ct

  // 3. Verify import through isolated target state container
  const destVault = new CredentialVault(DEFAULT_TIMEOUT_MS, targetContainer)
  destVault.importVault(exportedEnvelope)

  const isolatedImportVerified = destVault.hasVault() && destVault.isLocked()

  // 4. Unlock with rehearsal passphrase and verify recovered seeds
  const unlocked = await destVault.unlock(rehearsalPassphrase)
  if (!unlocked) {
    throw new Error('Recovery rehearsal failed: unable to unlock imported vault with rehearsal passphrase')
  }

  const recoveredSeeds = destVault.getSeeds()
  const syntheticSeedsVerified = !!recoveredSeeds &&
    recoveredSeeds.credentialSeed === syntheticMaterial.credentialSeed &&
    recoveredSeeds.nullifierSeed === syntheticMaterial.nullifierSeed

  if (!syntheticSeedsVerified) {
    throw new Error('Recovery rehearsal failed: recovered seeds do not match synthetic material')
  }

  // 5. Clean up rehearsal state in memory and isolated storage
  sourceVault.destroy()
  destVault.destroy()

  // 6. Verify the user's actual credentials were completely untouched
  const finalLiveStorage = (typeof window !== 'undefined' && window.localStorage)
    ? window.localStorage.getItem(VAULT_STORAGE_KEY)
    : null
  const originalCredentialsUntouched = originalLiveStorage === finalLiveStorage

  if (!originalCredentialsUntouched) {
    throw new Error('Safety boundary violated: live credentials storage was modified during recovery rehearsal')
  }

  // 7. Mark rehearsal completed in safe UI preferences if enabled
  const markCompleted = options?.markCompleted ?? true
  let rehearsalCompleted = false
  if (markCompleted) {
    const prefStorage = options?.preferencesStorage ??
      ((typeof window !== 'undefined' && window.localStorage) ? window.localStorage : undefined)
    if (prefStorage) {
      const safe = createSafeStorage(prefStorage)
      const currentPrefs = safe.getUiPreferences()
      safe.setUiPreferences({ ...currentPrefs, vaultRecoveryRehearsed: true })
      rehearsalCompleted = true
    } else {
      rehearsalCompleted = true
    }
  }

  return {
    success: true,
    syntheticSeedsVerified,
    isolatedExportVerified,
    isolatedImportVerified,
    originalCredentialsUntouched,
    rehearsalCompleted,
    exportedEnvelope,
    timestamp: Date.now(),
  }
}

export function hasVaultRecoveryRehearsed(preferencesStorage?: Storage): boolean {
  const prefStorage = preferencesStorage ??
    ((typeof window !== 'undefined' && window.localStorage) ? window.localStorage : undefined)
  if (!prefStorage) return false
  const safe = createSafeStorage(prefStorage)
  return safe.getUiPreferences().vaultRecoveryRehearsed === true
}

export function resetVaultRecoveryRehearsal(preferencesStorage?: Storage): void {
  const prefStorage = preferencesStorage ??
    ((typeof window !== 'undefined' && window.localStorage) ? window.localStorage : undefined)
  if (!prefStorage) return
  const safe = createSafeStorage(prefStorage)
  const currentPrefs = safe.getUiPreferences()
  safe.setUiPreferences({ ...currentPrefs, vaultRecoveryRehearsed: false })
}
