type StorageName = 'localStorage' | 'sessionStorage'

export type PersistedUiPreferences = {
  currentView?: 'landing' | 'studio' | 'verify'
  selectedTier?: 'silent' | 'source' | 'seal'
}

export const STORAGE_KEY = 'harpocrates:ui-preferences'
export const VAULT_STORAGE_KEY = 'harpocrates:credential-vault'
const VIEWS = new Set(['landing', 'studio', 'verify'])
const TIERS = new Set(['silent', 'source', 'seal'])

export interface CrossTabStorageChangeEvent {
  key: string | null
  oldValue: string | null
  newValue: string | null
  storageArea: Storage | null
}

export type CrossTabStorageListener = (change: CrossTabStorageChangeEvent) => void

/**
 * Register a cross-tab storage change listener.
 * In web browsers, window fires a 'storage' event when another tab or window
 * modifies localStorage.
 *
 * Handles both key-specific events and storage-wide clear events (where event.key is null).
 * Returns an unregister cleanup function.
 */
export function addCrossTabStorageListener(
  targetKey: string,
  listener: CrossTabStorageListener,
): () => void {
  if (typeof window === 'undefined' || typeof window.addEventListener !== 'function') {
    return () => {}
  }

  const handler = (event: StorageEvent) => {
    // If event.storageArea is present, ensure it targets localStorage
    if (event.storageArea && event.storageArea !== window.localStorage) {
      return
    }

    // Match exact key or storage-wide clear event (where key is null)
    if (event.key === targetKey || event.key === null) {
      listener({
        key: event.key,
        oldValue: event.oldValue,
        newValue: event.newValue,
        storageArea: event.storageArea,
      })
    }
  }

  window.addEventListener('storage', handler)
  return () => {
    window.removeEventListener('storage', handler)
  }
}

/**
 * The only application data permitted in browser storage is:
 * - currentView: the active public navigation view
 * - selectedTier: the active public identity-tier selection
 *
 * Everything else is excluded by construction. In particular, seeds, proof
 * witnesses, generated proofs, and raw private inputs must remain in memory.
 * 
 * Note: Credential seeds may be stored locally ONLY in the encrypted VaultEnvelope 
 * managed by `CredentialVault`, which provides explicit lock/unlock semantics.
 */
function sanitizePreferences(value: unknown): PersistedUiPreferences {
  if (!value || typeof value !== 'object') return {}

  const candidate = value as Record<string, unknown>
  const safe: PersistedUiPreferences = {}

  if (typeof candidate.currentView === 'string' && VIEWS.has(candidate.currentView)) {
    safe.currentView = candidate.currentView as PersistedUiPreferences['currentView']
  }
  if (typeof candidate.selectedTier === 'string' && TIERS.has(candidate.selectedTier)) {
    safe.selectedTier = candidate.selectedTier as PersistedUiPreferences['selectedTier']
  }

  return safe
}

function browserStorage(name: StorageName): Storage {
  return window[name]
}

function createSafeStorage(name: StorageName) {
  return {
    setItem(key: string, value: string) {
      browserStorage(name).setItem(key, value)
    },

    getItem(key: string): string | null {
      return browserStorage(name).getItem(key)
    },

    removeItem(key: string) {
      browserStorage(name).removeItem(key)
    },

    setUiPreferences(value: PersistedUiPreferences) {
      const safe = sanitizePreferences(value)
      browserStorage(name).setItem(STORAGE_KEY, JSON.stringify(safe))
    },

    getUiPreferences(): PersistedUiPreferences {
      const stored = browserStorage(name).getItem(STORAGE_KEY)
      if (!stored) return {}

      try {
        return sanitizePreferences(JSON.parse(stored))
      } catch {
        return {}
      }
    },

    clearUiPreferences() {
      browserStorage(name).removeItem(STORAGE_KEY)
    },

    onKeyChange(key: string, listener: CrossTabStorageListener): () => void {
      return addCrossTabStorageListener(key, listener)
    },
  }
}

export const safeLocalStorage = createSafeStorage('localStorage')
export const safeSessionStorage = createSafeStorage('sessionStorage')
