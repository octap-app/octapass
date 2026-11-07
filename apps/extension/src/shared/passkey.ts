// Passkey request messages, shared by the page script, the content script, the prompt and the
// service worker (background/passkeyRequests.ts).

import type { PublicKeyCredentialCreationOptionsJSON, PublicKeyCredentialRequestOptionsJSON } from '@octapass/core';

export const PASSKEY_PORT = 'octapass-passkey';

export type PasskeyCall =
  | { kind: 'create'; options: PublicKeyCredentialCreationOptionsJSON }
  | { kind: 'get'; options: PublicKeyCredentialRequestOptionsJSON };

export type PasskeyResult =
  | { kind: 'credential'; credential: unknown }
  /** The user wants the browser's own passkey flow (another device, a security key…). */
  | { kind: 'fallback' }
  | { kind: 'error'; name: string; message: string };

/** Sent to the content script on the passkey port. */
export type PasskeyPortMessage = { type: 'pending'; requestId: string } | { type: 'done'; result: PasskeyResult };

/** What the prompt shows. */
export interface PasskeyPrompt {
  kind: PasskeyCall['kind'];
  origin: string;
  rpId: string;
  rpName?: string;
  userName?: string;
}
