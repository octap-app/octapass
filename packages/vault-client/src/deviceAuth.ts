// The two-gate device-auth model (plans/03-security-model.md, "Device unlock rules"). Settings are
// per device and never synced. Opening the app asks for the device's own lock where one exists;
// autofill has its own gate so it can fill directly while the vault is unlocked. Reveal, copy and
// export stay gated even on a device with no lock, where the master password is the only gate left.
//
// The web vault never offers a gateless mode: a web page can't tell who's at the keyboard.

export interface DeviceAuthSettings {
  /** Ask for the device lock when the app or extension opens, wherever the OS provides one. */
  requireDeviceAuthOnAppOpen: boolean;
  /** Ask for the device lock on every fill. Off: fill directly while the vault is unlocked. */
  requireDeviceAuthOnAutofill: boolean;
  /** Reveal, copy and export are always gated: device auth, or the master password without one. */
  requireDeviceAuthOnRevealCopy: boolean;
  /**
   * Confirm it's you before a card's security code is filled, even when "Ask on every fill" is off
   * (plan 05). Off by default. Declining still fills the rest of the card.
   */
  requireReauthForCvv: boolean;
}

export const DEFAULT_DEVICE_AUTH_SETTINGS: DeviceAuthSettings = {
  requireDeviceAuthOnAppOpen: true,
  requireDeviceAuthOnAutofill: true,
  requireDeviceAuthOnRevealCopy: true,
  requireReauthForCvv: false,
};

export type DeviceAuthGate = 'appOpen' | 'autofill' | 'revealCopy';

export interface DeviceAuthContext {
  settings: DeviceAuthSettings;
  /**
   * The OS offers a lock this app can use (a platform passkey with PRF, or the desktop app). On a
   * device without one there is nothing to verify with, so opening and filling don't prompt.
   */
  osCredential: boolean;
  /** The web vault never offers a gateless mode, whatever the settings say. */
  webVault?: boolean;
}

export interface DeviceAuthDecision {
  required: boolean;
  /**
   * No OS credential, so the Google-Password-Manager parity path applies: no prompt for opening or
   * autofill. Reveal/copy/export still need the master password. State this at setup time.
   */
  lockless: boolean;
}

/** Whether `gate` needs the user to confirm it's them, per the per-device settings. */
export function deviceAuthDecision(gate: DeviceAuthGate, { settings, osCredential, webVault = false }: DeviceAuthContext): DeviceAuthDecision {
  const lockless = !osCredential;
  if (gate === 'revealCopy') return { required: true, lockless };
  // A web page can't tell who's at the keyboard, so the web vault is never gateless.
  if (webVault) return { required: true, lockless: false };
  // With no OS credential there is nothing to verify with (Google Password Manager parity).
  if (lockless) return { required: false, lockless: true };
  return { required: gate === 'appOpen' ? settings.requireDeviceAuthOnAppOpen : settings.requireDeviceAuthOnAutofill, lockless: false };
}

/** The setting behind each gate. */
export function deviceAuthSettingKey(gate: DeviceAuthGate): keyof DeviceAuthSettings {
  if (gate === 'appOpen') return 'requireDeviceAuthOnAppOpen';
  if (gate === 'autofill') return 'requireDeviceAuthOnAutofill';
  return 'requireDeviceAuthOnRevealCopy';
}
