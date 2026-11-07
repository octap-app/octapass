// Device unlock with a platform passkey and the WebAuthn PRF extension (plan 11, "Device unlock").
// Everything here runs on the page and talks only to the device's authenticator, never a server.
// Both services share it; only the ASK wrapping differs (WASM core in the worker, WebCrypto in the mock).

import { VaultError } from './errors';
import type { WebAuthnAssertion, WebAuthnAttestation, WebAuthnCreationOptions, WebAuthnRequestOptions } from './remote/api';
import { base64UrlDecode, base64UrlEncode } from './tools/encoding';
import type { DevicePlatform } from './types';

export const DEVICE_LABELS: Record<DevicePlatform, string> = {
  mac: 'Touch ID',
  windows: 'Windows Hello',
  ios: 'Face ID / passcode',
  android: 'your device',
  other: 'your device',
};

export function detectPlatform(userAgent: string = navigator.userAgent, maxTouchPoints: number = navigator.maxTouchPoints ?? 0): DevicePlatform {
  if (/iPhone|iPad|iPod/.test(userAgent)) return 'ios';
  // iPadOS reports itself as a Mac; touch support gives it away.
  if (/Macintosh/.test(userAgent)) return maxTouchPoints > 1 ? 'ios' : 'mac';
  if (/Windows/.test(userAgent)) return 'windows';
  if (/Android/.test(userAgent)) return 'android';
  return 'other';
}

/**
 * Whether this page can make a passkey for its own host (`rp.id = location.hostname`). Firefox
 * extension pages can't: Firefox lets an extension use WebAuthn only for a website's domain it has
 * host permissions for, never for the extension itself, and answers "SecurityError: The operation is
 * insecure" (plan 13 History, 2026-11-04).
 */
export function canMakeDevicePasskey(protocol: string = typeof location === 'undefined' ? '' : location.protocol): boolean {
  return protocol !== 'moz-extension:';
}

/** A device-local authenticator that verifies the user (biometric or the device's own PIN/password). */
export async function isPlatformAuthenticatorAvailable(protocol?: string): Promise<boolean> {
  if (typeof PublicKeyCredential === 'undefined' || !navigator.credentials || !canMakeDevicePasskey(protocol)) return false;
  try {
    const available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    if (!available) return false;
    // Newer browsers can tell us up front whether PRF works; older ones only tell us at enable time.
    const capabilities = (await (PublicKeyCredential as unknown as { getClientCapabilities?: () => Promise<Record<string, boolean>> }).getClientCapabilities?.()) ?? {};
    return capabilities['extension:prf'] !== false;
  } catch {
    return false;
  }
}

/**
 * The PRF input, SHA-256("octapass/v1/device-unlock"). A constant rather than a digest computed on
 * the spot: Safari only opens the prompt inside the click, so nothing may be awaited before it.
 */
export const DEVICE_UNLOCK_SALT = new Uint8Array([
  0x3d, 0xc2, 0x21, 0xa5, 0xe7, 0xfa, 0x0a, 0x32, 0x27, 0x54, 0xad, 0x77, 0xb8, 0x94, 0x25, 0xdc, 0xa5, 0xef, 0x9e, 0xd6, 0x30, 0xcb, 0x95, 0x18, 0x7e, 0x9d, 0xf0, 0x69, 0x44, 0x45, 0x7d, 0x96,
]);

interface PrfOutputs {
  prf?: { enabled?: boolean; results?: { first?: ArrayBuffer | ArrayBufferView } };
}

function toBytes(buffer: ArrayBuffer | ArrayBufferView): Uint8Array<ArrayBuffer> {
  const view = ArrayBuffer.isView(buffer) ? new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength) : new Uint8Array(buffer);
  return new Uint8Array(view);
}

// DOMException isn't an Error subclass everywhere, so these read its fields directly.
const errorName = (error: unknown) => (typeof error === 'object' && error !== null && typeof (error as { name?: unknown }).name === 'string' ? (error as { name: string }).name : '');

/** The browser's own words ("NotAllowedError: …"), kept on the error so the screen can show them. */
function reason(error: unknown): string {
  const message = (error as { message?: unknown } | null)?.message;
  if (!errorName(error)) return String(error);
  return typeof message === 'string' && message ? `${errorName(error)}: ${message}` : errorName(error);
}

/**
 * NotAllowedError covers a dismissed prompt and most authenticator failures alike (browsers hide
 * which, by design), so it reads as "didn't finish" with the browser's reason attached.
 */
function mapWebAuthnError(error: unknown): never {
  if (error instanceof VaultError) throw error;
  const name = errorName(error);
  if (name === 'NotAllowedError' || name === 'AbortError') throw new VaultError('deviceUnlockCancelled', reason(error));
  // SecurityError: this page's origin can't use a passkey for its own host (an IP address, or a
  // Firefox extension page). Nothing on the device broke, so it reads as "not here".
  if (name === 'NotSupportedError' || name === 'SecurityError') throw new VaultError('deviceUnlockUnsupported', reason(error));
  throw new VaultError('deviceUnlockFailed', reason(error));
}

export interface DeviceCredential {
  id: Uint8Array<ArrayBuffer>;
  /** The PRF output, when the browser evaluates it while creating the passkey (Safari, Firefox). */
  prf?: Uint8Array<ArrayBuffer>;
}

/** Creates a platform passkey for this site. Throws `deviceUnlockUnsupported` when PRF isn't available. */
export async function createDeviceCredential(email: string): Promise<DeviceCredential> {
  let credential: PublicKeyCredential | null;
  try {
    credential = (await navigator.credentials.create({
      publicKey: {
        rp: { id: location.hostname, name: 'Octa Pass' },
        user: { id: crypto.getRandomValues(new Uint8Array(16)), name: email, displayName: email },
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        pubKeyCredParams: [
          { type: 'public-key', alg: -7 },
          { type: 'public-key', alg: -257 },
        ],
        authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'required', residentKey: 'discouraged' },
        // Asking for the output now saves a second prompt where the browser can give it. Firefox on
        // macOS also needs a salt here: without one it hands the system an empty PRF input.
        extensions: { prf: { eval: { first: DEVICE_UNLOCK_SALT } } } as AuthenticationExtensionsClientInputs,
        timeout: 120_000,
      },
    })) as PublicKeyCredential | null;
  } catch (error) {
    mapWebAuthnError(error);
  }
  if (!credential) throw new VaultError('deviceUnlockCancelled');
  const prf = (credential.getClientExtensionResults() as PrfOutputs).prf;
  const first = prf?.results?.first;
  if (!first && !prf?.enabled) throw new VaultError('deviceUnlockUnsupported');
  return { id: toBytes(credential.rawId), ...(first ? { prf: toBytes(first) } : {}) };
}

/** Asks the device to verify the user and returns the credential's 32-byte PRF output. */
export async function evaluatePrf(credentialId: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
  let assertion: PublicKeyCredential | null;
  try {
    assertion = (await navigator.credentials.get({
      publicKey: {
        rpId: location.hostname,
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        allowCredentials: [{ type: 'public-key', id: credentialId }],
        userVerification: 'required',
        extensions: { prf: { eval: { first: DEVICE_UNLOCK_SALT } } } as AuthenticationExtensionsClientInputs,
        timeout: 120_000,
      },
    })) as PublicKeyCredential | null;
  } catch (error) {
    mapWebAuthnError(error);
  }
  if (!assertion) throw new VaultError('deviceUnlockCancelled');
  const first = (assertion.getClientExtensionResults() as PrfOutputs).prf?.results?.first;
  if (!first) throw new VaultError('deviceUnlockUnsupported');
  return toBytes(first);
}

// A passkey made for an account whose PRF output still needs a second prompt.
let unconfirmed: { email: string; id: Uint8Array<ArrayBuffer> } | undefined;

/**
 * Turning device unlock on: a new passkey and its PRF output. Where the browser only gives the
 * output when the passkey is used, that second prompt runs straight away; if the browser refuses it
 * without a fresh click (Safari), this throws `deviceUnlockConfirm` and the next call reuses the passkey.
 */
export async function setUpDeviceCredential(email: string): Promise<Required<DeviceCredential>> {
  try {
    let id = unconfirmed?.email === email ? unconfirmed.id : undefined;
    if (!id) {
      const created = await createDeviceCredential(email);
      if (created.prf) return { id: created.id, prf: created.prf };
      id = created.id;
    }
    try {
      const prf = await evaluatePrf(id);
      unconfirmed = undefined;
      return { id, prf };
    } catch (error) {
      if (!(error instanceof VaultError && error.code === 'deviceUnlockCancelled')) throw error;
      unconfirmed = { email, id };
      throw new VaultError('deviceUnlockConfirm', error.message);
    }
  } catch (error) {
    if (error instanceof VaultError && error.code === 'deviceUnlockConfirm') throw error;
    unconfirmed = undefined;
    // Nothing was on yet, so nothing "stopped working".
    if (error instanceof VaultError && error.code === 'deviceUnlockFailed') throw new VaultError('deviceUnlockSetupFailed', error.message);
    throw error;
  }
}

// ---------- Security keys for two-step sign-in (plan 03, "Account 2FA") ----------
// These run against the server's relying party, so they only work on the web vault's own site.

/** Whether this page can use security keys registered for `rpId`. */
export function securityKeysSupported(rpId: string | undefined, hostname: string = typeof location === 'undefined' ? '' : location.hostname): boolean {
  if (!rpId || typeof PublicKeyCredential === 'undefined' || typeof navigator === 'undefined' || !navigator.credentials) return false;
  return hostname === rpId || hostname.endsWith(`.${rpId}`);
}

function mapSecurityKeyError(error: unknown): never {
  if (error instanceof VaultError) throw error;
  if (error instanceof DOMException && (error.name === 'NotAllowedError' || error.name === 'AbortError')) throw new VaultError('securityKeyCancelled');
  // The key is already registered for this account (excludeCredentials matched).
  if (error instanceof DOMException && error.name === 'InvalidStateError') throw new VaultError('alreadyExists');
  if (error instanceof DOMException && (error.name === 'NotSupportedError' || error.name === 'SecurityError')) throw new VaultError('securityKeyUnsupported');
  throw new VaultError('securityKeyUnsupported');
}

const credentialDescriptor = (id: string): PublicKeyCredentialDescriptor => ({ type: 'public-key', id: base64UrlDecode(id) });

/** Asks for one of the account's security keys and returns its signed answer to the challenge. */
export async function getSecurityKeyAssertion(options: WebAuthnRequestOptions): Promise<WebAuthnAssertion> {
  let credential: PublicKeyCredential | null;
  try {
    credential = (await navigator.credentials.get({
      publicKey: {
        challenge: base64UrlDecode(options.challenge),
        rpId: options.rpId,
        allowCredentials: options.allowCredentials.map(credentialDescriptor),
        userVerification: options.userVerification,
        timeout: options.timeout,
      },
    })) as PublicKeyCredential | null;
  } catch (error) {
    mapSecurityKeyError(error);
  }
  if (!credential) throw new VaultError('securityKeyCancelled');
  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    credentialId: base64UrlEncode(toBytes(credential.rawId)),
    clientDataJson: base64UrlEncode(toBytes(response.clientDataJSON)),
    authenticatorData: base64UrlEncode(toBytes(response.authenticatorData)),
    signature: base64UrlEncode(toBytes(response.signature)),
  };
}

/** Registers a new security key or passkey with the server's options. */
export async function createSecurityKey(options: WebAuthnCreationOptions): Promise<WebAuthnAttestation> {
  let credential: PublicKeyCredential | null;
  try {
    credential = (await navigator.credentials.create({
      publicKey: {
        challenge: base64UrlDecode(options.challenge),
        rp: options.rp,
        user: { id: base64UrlDecode(options.user.id), name: options.user.name, displayName: options.user.displayName },
        pubKeyCredParams: options.algorithms.map((alg) => ({ type: 'public-key', alg })),
        excludeCredentials: options.excludeCredentials.map(credentialDescriptor),
        authenticatorSelection: { residentKey: 'discouraged', userVerification: 'discouraged' },
        attestation: 'none',
        timeout: options.timeout,
      },
    })) as PublicKeyCredential | null;
  } catch (error) {
    mapSecurityKeyError(error);
  }
  if (!credential) throw new VaultError('securityKeyCancelled');
  const response = credential.response as AuthenticatorAttestationResponse;
  return {
    credentialId: base64UrlEncode(toBytes(credential.rawId)),
    clientDataJson: base64UrlEncode(toBytes(response.clientDataJSON)),
    attestationObject: base64UrlEncode(toBytes(response.attestationObject)),
  };
}
