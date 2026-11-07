// The passkey prompt's line to the service worker. The prompt needs the session's state, unlocking,
// and the passkey calls, so it talks to the worker's UI port directly instead of loading the web
// vault's whole RemoteVaultService (and with it the generator's wordlists and strength checker).

import type { PasskeyMatch } from '@octapass/core';
import type { SessionState } from '@octapass/vault-client';
import type { VaultEngine } from '@octapass/vault-client/remote';
import type { ExtensionApi } from '../popup/service';
import { rpcClient, UI_PORT, type RpcClient } from '../shared/rpc';
import type { PasskeyPrompt } from '../shared/passkey';

export type SessionStatus = SessionState['status'];

type Snapshot = Awaited<ReturnType<VaultEngine['init']>>;

export interface PasskeyClient {
  /** Undefined until the service worker has answered. */
  status(): SessionStatus | undefined;
  onStatus(listener: () => void): () => void;
  unlock(password: string): Promise<void>;
  prompt(requestId: string): Promise<PasskeyPrompt>;
  matches(requestId: string): Promise<PasskeyMatch[]>;
  /** The titles of the user's logins for a page, by item id: shown next to each passkey. */
  titles(url: string): Promise<Map<string, string>>;
  approve(requestId: string, choice?: Pick<PasskeyMatch, 'itemId' | 'credentialId'>): Promise<void>;
  fallback(requestId: string): Promise<void>;
  cancel(requestId: string): Promise<void>;
}

function isSessionEvent(event: unknown): event is { type: 'session'; snapshot: Snapshot } {
  return typeof event === 'object' && event !== null && (event as { type?: unknown }).type === 'session';
}

export function passkeyClient(rpc: RpcClient = rpcClient(() => chrome.runtime.connect({ name: UI_PORT }))): PasskeyClient {
  let status: SessionStatus | undefined;
  const listeners = new Set<() => void>();
  const set = (next: SessionStatus) => {
    if (next === status) return;
    status = next;
    // Fetch and compile the WASM core while the user types the master password.
    if (next === 'locked') void rpc.call('preload', []).catch(() => undefined);
    for (const listener of listeners) listener();
  };
  rpc.onEvent((event) => {
    if (isSessionEvent(event)) set(event.snapshot.session.status);
  });
  void rpc.call('init', []).then(
    (snapshot) => set((snapshot as Snapshot).session.status),
    () => set('signedOut'),
  );

  const call =
    <K extends keyof ExtensionApi>(method: K) =>
    (...args: Parameters<ExtensionApi[K]>) =>
      rpc.call(method, args) as ReturnType<ExtensionApi[K]>;
  const siteItems = call('siteItems');

  return {
    status: () => status,
    onStatus: (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    unlock: async (password) => {
      await rpc.call('unlock', [password]);
    },
    prompt: call('passkeyPrompt'),
    matches: call('passkeyMatches'),
    titles: async (url) => new Map((await siteItems(url)).map((item) => [item.id, item.title])),
    approve: call('passkeyApprove'),
    fallback: call('passkeyFallback'),
    cancel: call('passkeyCancel'),
  };
}
