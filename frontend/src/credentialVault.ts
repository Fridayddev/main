import type { SeedPair } from './seedVault'
import {
  VAULT_STORAGE_KEY,
  addCrossTabStorageListener,
  type CrossTabStorageChangeEvent,
} from './safeStorage'

export { VAULT_STORAGE_KEY }

const VAULT_VERSION = 1
const PBKDF2_ITERATIONS = 600000
const DEFAULT_TIMEOUT_MS = 15 * 60 * 1000 // 15 minutes

export interface VaultEnvelope {
  v: number
  salt: string // hex
  iv: string // hex
  ct: string // hex (ciphertext)
}

export type VaultStatus = 'locked' | 'unlocked' | 'stale'

export type StaleReason = 'envelope-updated' | 'envelope-removed' | 'envelope-corrupted'

export type RecoveryAction = 'reload' | 'overwrite' | 'discard'

export interface PreservedActiveWork {
  readonly seeds: SeedPair
  readonly capturedAt: number
  readonly staleReason: StaleReason
  readonly customData?: unknown
}

export type VaultEvent =
  | { type: 'stale'; reason: StaleReason; preservedWork: PreservedActiveWork }
  | { type: 'recovered'; action: RecoveryAction }
  | { type: 'locked' }
  | { type: 'unlocked' }

export type VaultEventListener = (event: VaultEvent) => void

export interface RecoveryOptions {
  password?: string
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

  // Cross-tab change detection and active work recovery state
  private currentEnvelopeRaw: string | null = null
  private staleReason: StaleReason | null = null
  private preservedWork: PreservedActiveWork | null = null
  private customActiveWork: unknown = null
  private unsubscribeStorage: (() => void) | null = null
  private listeners: Set<VaultEventListener> = new Set()

  constructor(inactivityTimeoutMs = DEFAULT_TIMEOUT_MS) {
    this.inactivityTimeoutMs = inactivityTimeoutMs
    this.initStorageListener()
  }

  isLocked(): boolean {
    return this.memoryKey === null || this.seeds === null || this.isStale()
  }

  isStale(): boolean {
    return this.checkStaleness()
  }

  getStatus(): VaultStatus {
    if (this.isStale()) return 'stale'
    if (this.isLocked()) return 'locked'
    return 'unlocked'
  }

  getStaleReason(): StaleReason | null {
    return this.staleReason
  }

  hasPreservedWork(): boolean {
    return this.preservedWork !== null
  }

  getPreservedWork(): PreservedActiveWork | null {
    return this.preservedWork
  }

  setActiveWork(data: unknown): void {
    this.customActiveWork = data
  }

  getActiveWork(): unknown {
    return this.customActiveWork
  }

  getSeeds(): SeedPair | null {
    if (this.isStale()) {
      return null
    }
    this.resetTimeout()
    return this.seeds
  }

  hasVault(): boolean {
    return !!window.localStorage.getItem(VAULT_STORAGE_KEY)
  }

  checkStaleness(): boolean {
    if (this.staleReason !== null) {
      return true
    }

    // Only an unlocked session can become stale from external envelope modifications
    if (this.memoryKey !== null && this.seeds !== null) {
      const currentStored = window.localStorage.getItem(VAULT_STORAGE_KEY)
      if (currentStored !== this.currentEnvelopeRaw) {
        let reason: StaleReason = 'envelope-updated'
        if (!currentStored) {
          reason = 'envelope-removed'
        } else {
          try {
            const parsed = JSON.parse(currentStored)
            if (!parsed || typeof parsed !== 'object' || parsed.v !== VAULT_VERSION) {
              reason = 'envelope-corrupted'
            }
          } catch {
            reason = 'envelope-corrupted'
          }
        }
        this.invalidateStaleView(reason)
        return true
      }
    }
    return false
  }

  subscribe(listener: VaultEventListener): () => void {
    this.listeners.add(listener)
    return () => {
      this.listeners.delete(listener)
    }
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

    const envelopeJson = JSON.stringify(envelope)
    window.localStorage.setItem(VAULT_STORAGE_KEY, envelopeJson)
    this.currentEnvelopeRaw = envelopeJson
    this.clearPreservedWork()
    this.memoryKey = key
    this.seeds = { credentialSeed: seeds.credentialSeed, nullifierSeed: seeds.nullifierSeed }
    this.resetTimeout()
    this.notifyListeners({ type: 'unlocked' })
  }

  async unlock(password: string): Promise<boolean> {
    const stored = window.localStorage.getItem(VAULT_STORAGE_KEY)
    if (!stored) throw new Error('Vault is empty')

    let envelope: VaultEnvelope
    try {
      envelope = JSON.parse(stored)
    } catch {
      throw new Error('Vault corrupted: unable to parse envelope')
    }

    if (envelope.v !== VAULT_VERSION) {
      throw new Error(`Unsupported vault version: ${envelope.v}`)
    }

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
      
      this.currentEnvelopeRaw = stored
      this.clearPreservedWork()
      this.memoryKey = key
      this.seeds = {
        credentialSeed: seedsRaw.credentialSeed,
        nullifierSeed: seedsRaw.nullifierSeed,
      }
      this.resetTimeout()
      this.notifyListeners({ type: 'unlocked' })
      return true
    } catch {
      // Typically an OperationError if decryption fails due to bad password
      return false
    }
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
    this.notifyListeners({ type: 'locked' })
  }

  async recover(action: 'reload', options?: RecoveryOptions): Promise<boolean>
  async recover(action: 'overwrite', options: { password: string }): Promise<void>
  async recover(action: 'discard'): Promise<void>
  async recover(action: RecoveryAction, options?: RecoveryOptions): Promise<boolean | void> {
    if (action === 'discard') {
      this.clearPreservedWork()
      this.currentEnvelopeRaw = window.localStorage.getItem(VAULT_STORAGE_KEY)
      this.lock()
      this.notifyListeners({ type: 'recovered', action: 'discard' })
      return
    }

    if (action === 'reload') {
      this.clearPreservedWork()
      this.currentEnvelopeRaw = window.localStorage.getItem(VAULT_STORAGE_KEY)
      this.lock()

      let unlocked = false
      if (options?.password) {
        unlocked = await this.unlock(options.password)
      }

      this.notifyListeners({ type: 'recovered', action: 'reload' })
      return unlocked
    }

    if (action === 'overwrite') {
      if (!this.preservedWork?.seeds) {
        throw new Error('No preserved active work available to overwrite vault')
      }
      if (!options?.password) {
        throw new Error('Password required to overwrite vault envelope')
      }

      const seedsToPreserve: SeedPair = {
        credentialSeed: this.preservedWork.seeds.credentialSeed,
        nullifierSeed: this.preservedWork.seeds.nullifierSeed,
      }

      await this.setup(options.password, seedsToPreserve)
      this.notifyListeners({ type: 'recovered', action: 'overwrite' })
      return
    }

    throw new Error(`Unsupported recovery action: ${String(action)}`)
  }

  async handleRecoveryAction(action: RecoveryAction, options?: RecoveryOptions): Promise<boolean> {
    if (action === 'reload') {
      return await this.recover('reload', options)
    }
    if (action === 'overwrite') {
      if (!options?.password) {
        throw new Error('Password required to overwrite vault envelope')
      }
      await this.recover('overwrite', { password: options.password })
      return true
    }
    if (action === 'discard') {
      await this.recover('discard')
      return true
    }
    throw new Error(`Unsupported recovery action: ${String(action)}`)
  }

  destroy(): void {
    this.lock()
    this.clearPreservedWork()
    this.currentEnvelopeRaw = null
    window.localStorage.removeItem(VAULT_STORAGE_KEY)
    if (this.unsubscribeStorage) {
      this.unsubscribeStorage()
      this.unsubscribeStorage = null
    }
  }

  dispose(): void {
    if (this.unsubscribeStorage) {
      this.unsubscribeStorage()
      this.unsubscribeStorage = null
    }
    this.clearTimeout()
    this.listeners.clear()
  }

  private initStorageListener(): void {
    if (typeof window !== 'undefined' && typeof window.addEventListener === 'function') {
      this.unsubscribeStorage = addCrossTabStorageListener(
        VAULT_STORAGE_KEY,
        (change) => this.handleCrossTabStorageChange(change)
      )
    }
  }

  private handleCrossTabStorageChange(change: CrossTabStorageChangeEvent): void {
    // If vault is not unlocked and not stale, just track stored value
    if (this.isLocked() && !this.isStale()) {
      this.currentEnvelopeRaw = change.newValue
      return
    }

    // Already in stale recovery state
    if (this.isStale()) {
      return
    }

    const currentStored = window.localStorage.getItem(VAULT_STORAGE_KEY)
    if (currentStored === this.currentEnvelopeRaw) {
      return
    }

    let reason: StaleReason = 'envelope-updated'
    if (!currentStored) {
      reason = 'envelope-removed'
    } else {
      try {
        const parsed = JSON.parse(currentStored)
        if (!parsed || typeof parsed !== 'object' || parsed.v !== VAULT_VERSION) {
          reason = 'envelope-corrupted'
        }
      } catch {
        reason = 'envelope-corrupted'
      }
    }

    this.invalidateStaleView(reason)
  }

  private invalidateStaleView(reason: StaleReason): void {
    if (!this.seeds) return

    // Quarantine and preserve active work before zeroing active session
    this.preservedWork = {
      seeds: {
        credentialSeed: this.seeds.credentialSeed,
        nullifierSeed: this.seeds.nullifierSeed,
      },
      capturedAt: Date.now(),
      staleReason: reason,
      customData: this.customActiveWork,
    }

    this.staleReason = reason

    // Inactivity timeout must not silently discard preserved work
    this.clearTimeout()

    // Invalidate unlocked view and zero out active session references
    this.seeds.credentialSeed = ''
    this.seeds.nullifierSeed = ''
    this.seeds = null
    this.memoryKey = null

    this.notifyListeners({
      type: 'stale',
      reason,
      preservedWork: this.preservedWork,
    })
  }

  private clearPreservedWork(): void {
    if (this.preservedWork) {
      this.preservedWork.seeds.credentialSeed = ''
      this.preservedWork.seeds.nullifierSeed = ''
      this.preservedWork = null
    }
    this.staleReason = null
  }

  private notifyListeners(event: VaultEvent): void {
    for (const listener of this.listeners) {
      try {
        listener(event)
      } catch (err) {
        console.error('CredentialVault listener error:', err)
      }
    }
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
