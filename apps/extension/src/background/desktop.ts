// Unlock through the desktop app over native messaging (plan 13, J; apps/desktop/README.md). The
// app answers `get-session-key-wrap` after the user confirms with Touch ID or Windows Hello: the
// account key wrapped for this request only, under a key both sides derive from an X25519 exchange.
// The extension then unlocks through the engine's device-unlock path, as with a passkey's PRF output.

import { base64UrlDecode, base64UrlEncode, isVaultError, VaultError, type VaultErrorCode } from '@octapass/vault-client';

export const NATIVE_HOST = 'app.octap.desktop';
const INFO = new TextEncoder().encode('octapass/v1/native-messaging');
const CHIP_INFO = new TextEncoder().encode('octapass/v1/native-messaging-chip');

export interface DesktopStatus {
  /** False when the app isn't running or isn't installed (no native messaging host), or refused this browser. */
  appRunning: boolean;
  /**
   * The app or its native host refused this browser (`browserNotTrusted`): release builds only
   * unlock through known browsers signed by their vendor (apps/desktop/README.md).
   */
  browserNotTrusted?: boolean;
  status?: 'signedOut' | 'locked' | 'unlocked';
  email?: string;
  serverUrl?: string;
  /** The app can ask for Touch ID / Windows Hello. */
  deviceUnlock?: boolean;
  /** "Touch ID", "Windows Hello"… */
  label?: string;
  /** The app stays unlocked (plan 18): it hands over the account key without a prompt while unlocked. */
  stayUnlocked?: boolean;
}

export interface SessionKeyWrap {
  email: string;
  serverUrl: string;
  deviceSalt: string;
  wrappedAsk: string;
  /** The 32-byte key that unwraps `wrappedAsk` (`Session.unlockWithDeviceKey`). */
  key: Uint8Array;
}

/** The desktop app's chip, for a local vault here: open `sealedSecret` with `key` (`openChipSecret`). */
export interface ChipSecretWrap {
  /** What the chip works from; keep it to ask again. Not a secret. */
  context: string;
  sealedSecret: string;
  key: Uint8Array;
}

/** `chrome.runtime.sendNativeMessage` to the app's host. */
export type NativeSend = (message: object) => Promise<unknown>;

type Reply = { ok: true; result: unknown } | { ok: false; error: { code: string; message?: string } };

const ERRORS: Record<string, VaultErrorCode> = {
  deviceUnlockCancelled: 'deviceUnlockCancelled',
  deviceUnlockFailed: 'deviceUnlockFailed',
  locked: 'locked',
  signedOut: 'locked',
  browserNotTrusted: 'deviceUnlockUnsupported',
};

/** The error for a browser the app won't unlock through; `appNotRunning` is the other `deviceUnlockUnsupported`. */
export const isBrowserNotTrusted = (error: unknown) => isVaultError(error, 'deviceUnlockUnsupported') && error.message === 'browserNotTrusted';

/** HKDF-SHA256(X25519(our secret, their public), salt = their public ‖ our public, "octapass/v1/native-messaging"). */
export async function deriveWrapKey(ours: CryptoKeyPair, theirPublic: Uint8Array, info: Uint8Array<ArrayBuffer> = INFO): Promise<Uint8Array<ArrayBuffer>> {
  const peer = await crypto.subtle.importKey('raw', theirPublic as Uint8Array<ArrayBuffer>, { name: 'X25519' }, false, []);
  const shared = await crypto.subtle.deriveBits({ name: 'X25519', public: peer }, ours.privateKey, 256);
  const ourPublic = new Uint8Array(await crypto.subtle.exportKey('raw', ours.publicKey));
  const salt = new Uint8Array([...theirPublic, ...ourPublic]);
  const ikm = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, ikm, 256));
}

export class DesktopLink {
  private nextId = 1;

  constructor(private readonly send: NativeSend) {}

  /** What the app reports; `appRunning: false` when it can't be reached at all. */
  async status(): Promise<DesktopStatus> {
    try {
      return (await this.request({ type: 'unlock-status' })) as DesktopStatus;
    } catch (error) {
      return isBrowserNotTrusted(error) ? { appRunning: false, browserNotTrusted: true } : { appRunning: false };
    }
  }

  /** Asks the app to unlock itself (its own Touch ID / Windows Hello prompt). */
  async unlockApp(): Promise<void> {
    await this.request({ type: 'unlock' });
  }

  /** The account key, wrapped for this request after the user confirms in the app. */
  async sessionKey(): Promise<SessionKeyWrap> {
    const pair = (await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits'])) as CryptoKeyPair;
    const publicKey = base64UrlEncode(new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey)));
    const result = (await this.request({ type: 'get-session-key-wrap', publicKey })) as Omit<SessionKeyWrap, 'key'> & { ephemeralPublicKey: string };
    const key = await deriveWrapKey(pair, base64UrlDecode(result.ephemeralPublicKey));
    return { email: result.email, serverUrl: result.serverUrl, deviceSalt: result.deviceSalt, wrappedAsk: result.wrappedAsk, key };
  }

  /**
   * The chip's secret for a local vault in this browser. With no `context`, the app makes a new
   * chip key. `undefined` when the computer has no chip to offer; throws when the app isn't there,
   * so a vault bound to it can say so.
   */
  async chipSecret(vaultId: string, context?: string): Promise<ChipSecretWrap | undefined> {
    const pair = (await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits'])) as CryptoKeyPair;
    const publicKey = base64UrlEncode(new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey)));
    const result = (await this.request({ type: 'local-chip-secret', publicKey, vaultId, ...(context ? { context } : {}) })) as { context: string; ephemeralPublicKey: string; sealedSecret: string } | null;
    if (!result) return undefined;
    const key = await deriveWrapKey(pair, base64UrlDecode(result.ephemeralPublicKey), CHIP_INFO);
    return { context: result.context, sealedSecret: result.sealedSecret, key };
  }

  private async request(message: object): Promise<unknown> {
    let reply: Reply;
    try {
      reply = (await this.send({ id: this.nextId++, ...message })) as Reply;
    } catch {
      throw new VaultError('deviceUnlockUnsupported', 'appNotRunning');
    }
    if (!reply) throw new VaultError('deviceUnlockUnsupported', 'appNotRunning');
    if (reply.ok) return reply.result;
    throw new VaultError(ERRORS[reply.error.code] ?? 'deviceUnlockFailed', reply.error.code);
  }
}
