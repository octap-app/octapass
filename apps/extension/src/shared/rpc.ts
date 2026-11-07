// Request/response calls and server events over a `chrome.runtime` port, between the extension's
// own pages (popup, side panel, passkey prompt) and the service worker. Values go through the wire
// encoding, and errors keep their `VaultError` code so the web vault's screens show the right message.

import { VaultError, type VaultErrorCode } from '@octapass/vault-client';
import { decodeWire, encodeWire } from './wire';

export const UI_PORT = 'octapass-ui';

/** Port traffic resets the service worker's idle timer; while a page is open, keep it awake. */
const KEEPALIVE_MS = 20_000;

export interface RpcRequest {
  id: number;
  method: string;
  args: unknown[];
}

export interface SerializedError {
  name: string;
  message: string;
  code?: VaultErrorCode;
}

export type RpcResponse = { id: number; ok: true; value: unknown } | { id: number; ok: false; error: SerializedError };
export type RpcMessage = RpcResponse | { event: unknown } | { ping: true };

export function serializeError(error: unknown): SerializedError {
  if (error instanceof VaultError) return { name: error.name, message: error.message, code: error.code };
  if (error instanceof Error) return { name: error.name, message: error.message };
  return { name: 'Error', message: String(error) };
}

export function deserializeError(error: SerializedError): Error {
  if (error.code) return new VaultError(error.code, error.message);
  return Object.assign(new Error(error.message), { name: error.name });
}

export interface RpcClient {
  call(method: string, args: unknown[]): Promise<unknown>;
  onEvent(listener: (event: unknown) => void): () => void;
}

/**
 * The page side. The service worker can be stopped while a page sits idle, which drops the port;
 * the next call reconnects, and calls in flight at that moment fail rather than hang.
 */
export function rpcClient(connect: () => chrome.runtime.Port): RpcClient {
  const pending = new Map<number, { resolve: (value: unknown) => void; reject: (error: Error) => void }>();
  const listeners = new Set<(event: unknown) => void>();
  let nextId = 1;
  let port: chrome.runtime.Port | undefined;
  // Encoding is async (Blobs); this keeps requests in the order they were made.
  let sending: Promise<void> = Promise.resolve();

  const open = (): chrome.runtime.Port => {
    if (port) return port;
    const current = connect();
    const keepalive = setInterval(() => current.postMessage({ ping: true }), KEEPALIVE_MS);
    current.onMessage.addListener((raw: RpcMessage) => {
      if ('ping' in raw) return;
      if ('event' in raw) {
        const event = decodeWire(raw.event);
        for (const listener of listeners) listener(event);
        return;
      }
      const call = pending.get(raw.id);
      if (!call) return;
      pending.delete(raw.id);
      if (raw.ok) call.resolve(decodeWire(raw.value));
      else call.reject(deserializeError(raw.error));
    });
    current.onDisconnect.addListener(() => {
      clearInterval(keepalive);
      if (port === current) port = undefined;
      for (const call of pending.values()) call.reject(new VaultError('serverUnreachable', 'The extension restarted. Try again.'));
      pending.clear();
    });
    port = current;
    return current;
  };

  // Connect now, so the service worker sends the current state straight away.
  open();

  return {
    call(method, args) {
      const id = nextId++;
      return new Promise((resolve, reject) => {
        pending.set(id, { resolve, reject });
        sending = sending.then(async () => {
          try {
            open().postMessage({ id, method, args: (await encodeWire(args)) as unknown[] } satisfies RpcRequest);
          } catch (error) {
            pending.delete(id);
            reject(error instanceof Error ? error : new Error(String(error)));
          }
        });
      });
    },
    onEvent(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
  };
}

export type Handlers = Record<string, (...args: never[]) => unknown>;

/** The service worker side: answers calls on `port` with `handlers`; any other method is refused. */
export function serveRpc(port: chrome.runtime.Port, handlers: Handlers | Promise<Handlers>): void {
  // Listening right away matters: a port drops messages that arrive before a listener exists, so a
  // page that connects while the worker is still starting would wait forever.
  port.onMessage.addListener((raw: RpcRequest | { ping: true }) => {
    if ('ping' in raw) return;
    const { id, method } = raw;
    void (async () => {
      let response: RpcResponse;
      try {
        const ready = await handlers;
        if (!Object.hasOwn(ready, method)) throw new Error(`Unknown method ${method}`);
        const args = decodeWire(raw.args) as never[];
        response = { id, ok: true, value: await encodeWire(await ready[method]!(...args)) };
      } catch (error) {
        response = { id, ok: false, error: serializeError(error) };
      }
      try {
        port.postMessage(response);
      } catch {
        // The page closed while we worked.
      }
    })();
  });
}

/** Sends a server event to one page. */
export async function postEvent(port: chrome.runtime.Port, event: unknown): Promise<void> {
  const message: RpcMessage = { event: await encodeWire(event) };
  try {
    port.postMessage(message);
  } catch {
    // Disconnected.
  }
}
