// The autofill gate (plan 03, the two-gate model). The setting is per device and never synced; the
// popup mirrors it into `chrome.storage.local` so the service worker can read it while filling.
//
// ON (the default): each fill asks the device's lock. OFF: filling works directly while the vault
// is unlocked. A device with no device unlock enrolled can't verify anything, so it follows Google
// Password Manager: no prompt, and the settings say so plainly.

import { deviceAuthDecision, DEFAULT_DEVICE_AUTH_SETTINGS, type DeviceAuthSettings } from '@octapass/vault-client';

export const DEVICE_AUTH_KEY = 'octapass:deviceAuth';
/** The popup's message while an autofill waits for its confirmation window. */
export const FILL_AUTH_PATH = '/auth/fill/';

const TIMEOUT_MS = 2 * 60_000;

export async function readDeviceAuthSettings(): Promise<DeviceAuthSettings> {
  const stored = (await chrome.storage.local.get(DEVICE_AUTH_KEY))[DEVICE_AUTH_KEY] as Partial<DeviceAuthSettings> | undefined;
  return { ...DEFAULT_DEVICE_AUTH_SETTINGS, ...stored };
}

interface Pending {
  resolve: (approved: boolean) => void;
  windowId?: number;
  timer: ReturnType<typeof setTimeout>;
}

export interface AutofillAuthOptions {
  /** Device unlock is enrolled here, so `confirmIdentity({ device: true })` can work. */
  canConfirmWithDevice: () => Promise<boolean>;
  openPrompt: (id: string) => Promise<number | undefined>;
  closePrompt: (windowId: number) => Promise<void> | void;
  /** The worker must stay awake while a prompt waits. */
  busy?: (waiting: boolean) => void;
  /** Test seam: the mirrored settings, instead of `chrome.storage.local`. */
  settings?: () => Promise<DeviceAuthSettings>;
  /** Plan 18: staying unlocked, filling doesn't ask (the security code's own re-prompt still can). */
  stayUnlocked?: () => boolean;
  now?: () => number;
}

export class AutofillAuth {
  private readonly pending = new Map<string, Pending>();

  constructor(private readonly options: AutofillAuthOptions) {}

  /** Whether a fill would ask now. A fill on page load happens only when it wouldn't: it never prompts. */
  async wouldAsk(): Promise<boolean> {
    return (await this.gate()).required;
  }

  /** True: fill now. False: the user closed the prompt or answered no. */
  async request(): Promise<boolean> {
    return !(await this.gate()).required || this.prompt();
  }

  /**
   * Filling a card: one prompt covers both the fill gate and the security code. With the code's
   * re-prompt on, the prompt appears even where the fill gate wouldn't ask (it's off, or the device
   * has no lock, where the master password answers it). Answering no to the code alone still fills
   * the rest of the card.
   */
  async requestCard(hasCvv: boolean): Promise<{ fill: boolean; cvv: boolean }> {
    const { required, settings } = await this.gate();
    const askForCvv = hasCvv && settings.requireReauthForCvv;
    if (!required && !askForCvv) return { fill: true, cvv: true };
    const approved = await this.prompt();
    return { fill: approved || !required, cvv: approved };
  }

  private async gate(): Promise<{ required: boolean; settings: DeviceAuthSettings }> {
    const settings = await (this.options.settings ?? readDeviceAuthSettings)();
    if (this.options.stayUnlocked?.()) return { required: false, settings };
    const osCredential = await this.options.canConfirmWithDevice().catch(() => false);
    return { required: deviceAuthDecision('autofill', { settings, osCredential }).required, settings };
  }

  private async prompt(): Promise<boolean> {
    const id = crypto.randomUUID();
    const windowId = await this.options.openPrompt(id);
    return new Promise<boolean>((resolve) => {
      const timer = setTimeout(() => this.answer(id, false), TIMEOUT_MS);
      this.pending.set(id, { resolve, timer, ...(windowId !== undefined ? { windowId } : {}) });
      this.options.busy?.(true);
    });
  }

  /** The prompt page's answer. */
  answer(id: string, approved: boolean): void {
    const pending = this.pending.get(id);
    if (!pending) return;
    this.pending.delete(id);
    clearTimeout(pending.timer);
    if (this.pending.size === 0) this.options.busy?.(false);
    if (pending.windowId !== undefined) void this.options.closePrompt(pending.windowId);
    pending.resolve(approved);
  }

  /** A prompt window the user closed. */
  windowClosed(windowId: number): void {
    for (const [id, pending] of this.pending) if (pending.windowId === windowId) this.answer(id, false);
  }

  /** Locking or signing out ends every waiting fill. */
  cancelAll(): void {
    for (const id of [...this.pending.keys()]) this.answer(id, false);
  }
}
