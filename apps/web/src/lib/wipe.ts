/** Removes this app's preferences from localStorage. Vault data never lives there. */
export function wipeLocalPreferences(): void {
  try {
    for (const key of Object.keys(localStorage)) if (key.startsWith('octapass:')) localStorage.removeItem(key);
  } catch {
    // Storage may be unavailable; nothing to wipe then.
  }
}
