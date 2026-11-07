// Passkey requests between a page and the Octa Pass prompt. The content script opens a port for
// each `navigator.credentials` call and frames the prompt (an extension page) with the request ID;
// only the prompt, never the content script, can approve. Closing the port cancels the request.

import type { PasskeyCaller, PasskeyMatch, PublicKeyCredentialCreationOptionsJSON, PublicKeyCredentialRequestOptionsJSON } from '@octapass/core';
import type { PasskeyCall, PasskeyPrompt, PasskeyResult } from '../shared/passkey';
import { PasskeyError, toPasskeyError, type PasskeyAuthenticator } from './passkeys';

interface Pending {
  call: PasskeyCall;
  caller: PasskeyCaller;
  tabId: number;
  respond: (result: PasskeyResult) => void;
}

function hostOf(origin: string): string {
  return new URL(origin).hostname;
}

/** Just enough shape checking to show a prompt; the core validates the rest. */
export function parseCall(value: unknown): PasskeyCall | undefined {
  const call = value as { kind?: unknown; options?: Record<string, unknown> } | null;
  if (!call || typeof call.options !== 'object' || call.options === null || typeof call.options.challenge !== 'string') return undefined;
  if (call.kind === 'create') {
    const { rp, user } = call.options as { rp?: { name?: unknown }; user?: { name?: unknown; id?: unknown } };
    if (typeof rp?.name !== 'string' || typeof user?.name !== 'string' || typeof user.id !== 'string') return undefined;
    return { kind: 'create', options: call.options as unknown as PublicKeyCredentialCreationOptionsJSON };
  }
  if (call.kind === 'get') return { kind: 'get', options: call.options as unknown as PublicKeyCredentialRequestOptionsJSON };
  return undefined;
}

export class PasskeyRequests {
  private readonly pending = new Map<string, Pending>();

  constructor(private readonly authenticator: PasskeyAuthenticator) {}

  /** A page asked; returns the request ID for the prompt. */
  open(call: PasskeyCall, caller: PasskeyCaller, tabId: number, respond: (result: PasskeyResult) => void): string {
    const id = crypto.randomUUID();
    this.pending.set(id, { call, caller, tabId, respond });
    return id;
  }

  /** The page went away or gave up. */
  drop(id: string): void {
    this.pending.delete(id);
  }

  prompt(id: string, tabId: number | undefined): PasskeyPrompt {
    const { call, caller } = this.get(id, tabId);
    if (call.kind === 'create') {
      const { rp, user } = call.options;
      return { kind: 'create', origin: caller.origin, rpId: rp.id ?? hostOf(caller.origin), rpName: rp.name, userName: user.name };
    }
    return { kind: 'get', origin: caller.origin, rpId: call.options.rpId ?? hostOf(caller.origin) };
  }

  /** The passkeys the user can pick from (unlocked only). */
  async matches(id: string, tabId: number | undefined): Promise<PasskeyMatch[]> {
    const { call, caller } = this.get(id, tabId);
    if (call.kind !== 'get') return [];
    return this.authenticator.find(call.options, caller);
  }

  /** The user chose Octa Pass (and, to sign in, one of its passkeys). */
  async approve(id: string, tabId: number | undefined, choice?: Pick<PasskeyMatch, 'itemId' | 'credentialId'>): Promise<void> {
    const request = this.get(id, tabId);
    try {
      const credential =
        request.call.kind === 'create'
          ? await this.authenticator.create(request.call.options, request.caller)
          : await this.authenticator.assert(request.call.options, request.caller, choice ?? missingChoice());
      this.finish(id, { kind: 'credential', credential });
    } catch (error) {
      const failure = toPasskeyError(error);
      // Locked again in the meantime: let the prompt unlock and try again.
      if (failure.message === 'locked') throw failure;
      this.finish(id, { kind: 'error', name: failure.domName, message: failure.message });
    }
  }

  fallback(id: string, tabId: number | undefined): void {
    this.get(id, tabId);
    this.finish(id, { kind: 'fallback' });
  }

  cancel(id: string, tabId: number | undefined): void {
    this.get(id, tabId);
    this.finish(id, { kind: 'error', name: 'NotAllowedError', message: 'The user cancelled.' });
  }

  /** Only the prompt framed in the requesting tab may answer. */
  private get(id: string, tabId: number | undefined): Pending {
    const request = this.pending.get(id);
    if (!request || request.tabId !== tabId) throw new PasskeyError('NotAllowedError', 'This request has ended.');
    return request;
  }

  private finish(id: string, result: PasskeyResult): void {
    const request = this.pending.get(id);
    this.pending.delete(id);
    request?.respond(result);
  }
}

function missingChoice(): never {
  throw new PasskeyError('NotAllowedError', 'passkey_not_found');
}
