// The client of Octa Pass Connect (docs/developers/connect-api.md). No `vscode` import, so the
// tests run it against a real server on a real socket. It has no way to ask for a value, on
// purpose: this extension only ever holds names.

import { existsSync, readFileSync } from 'node:fs';
import * as http from 'node:http';
import { posix, win32 } from 'node:path';

const FOLDER = 'com.octapass.connect';
const MAX_RESPONSE = 8 * 1024 * 1024;
const REQUEST_TIMEOUT = 30_000;
/** Connect waits up to two minutes for the person to answer. */
const APPROVAL_TIMEOUT = 130_000;

export type Endpoint = { kind: 'socket'; path: string } | { kind: 'loopback'; host: string; port: number };

export type Failure =
  | 'not-running'
  | 'bad-endpoint'
  | 'timed-out'
  | 'cancelled'
  | 'bad-response'
  | 'bad-request'
  | 'unauthorized'
  | 'denied'
  | 'forbidden'
  | 'not-found'
  | 'locked'
  | 'busy'
  | 'failed';

export class ConnectError extends Error {
  constructor(
    readonly failure: Failure,
    message = '',
    readonly status?: number,
  ) {
    super(message || failure);
    this.name = 'ConnectError';
  }
}

export interface Paired {
  id: string;
  token: string;
  /** Unix seconds. */
  expiresAt: number;
}

export interface ItemField {
  name: string;
  secret: boolean;
}

export interface ItemRef {
  vault: string;
  item: string;
  itemId: string;
  type: string;
  fields: ItemField[];
}

export interface Place {
  env: NodeJS.ProcessEnv;
  platform: NodeJS.Platform;
  home: string;
}

/** The Connect folder in this system's per-user data folder. */
export function connectFolder({ env, platform, home }: Place): string {
  if (platform === 'win32') {
    return win32.join(env.APPDATA || win32.join(home, 'AppData', 'Roaming'), FOLDER);
  }
  if (platform === 'darwin') {
    return posix.join(home, 'Library', 'Application Support', FOLDER);
  }
  // The XDG spec has relative paths ignored, and the service does the same.
  const data = env.XDG_DATA_HOME;
  return posix.join(data && posix.isAbsolute(data) ? data : posix.join(home, '.local', 'share'), FOLDER);
}

/** `unix:/path` or `http://127.0.0.1:<port>` or `http://localhost:<port>`. Nothing else, so a token never leaves the machine. */
export function parseEndpoint(text: string): Endpoint | undefined {
  if (text.startsWith('unix:')) {
    const path = text.slice('unix:'.length);
    return path ? { kind: 'socket', path } : undefined;
  }
  const match = /^http:\/\/(127\.0\.0\.1|localhost):(\d{1,5})\/?$/.exec(text);
  const port = match ? portNumber(match[2]!) : undefined;
  return match && port ? { kind: 'loopback', host: match[1]!, port } : undefined;
}

function portNumber(text: string): number | undefined {
  const port = /^\d{1,5}$/.test(text) ? Number(text) : 0;
  return port >= 1 && port <= 65535 ? port : undefined;
}

/** In the order of the docs: `OCTAPASS_CONNECT`, the socket, the port file. */
export function findEndpoint(place: Place): Endpoint {
  const configured = place.env.OCTAPASS_CONNECT;
  if (configured) {
    const endpoint = parseEndpoint(configured);
    if (!endpoint) {
      throw new ConnectError('bad-endpoint');
    }
    return endpoint;
  }
  const folder = connectFolder(place);
  const join = place.platform === 'win32' ? win32.join : posix.join;
  const socket = join(folder, 'connect.sock');
  if (existsSync(socket)) {
    return { kind: 'socket', path: socket };
  }
  let text: string;
  try {
    text = readFileSync(join(folder, 'connect.port'), 'utf8');
  } catch {
    throw new ConnectError('not-running');
  }
  const port = portNumber(text.trim());
  if (!port) {
    throw new ConnectError('not-running');
  }
  return { kind: 'loopback', host: '127.0.0.1', port };
}

interface Reply {
  status: number;
  text: string;
}

interface Call {
  body?: unknown;
  signal?: AbortSignal;
  timeout?: number;
}

export class ConnectClient {
  constructor(
    private readonly endpoint: Endpoint,
    private readonly token?: string,
  ) {}

  async status(): Promise<{ unlocked: boolean }> {
    const value = await this.json('GET', '/v1/status');
    if (!isRecord(value) || typeof value.unlocked !== 'boolean') {
      throw new ConnectError('bad-response');
    }
    return { unlocked: value.unlocked };
  }

  /** Waits while the person is asked. Abort `signal` to stop waiting. */
  async pair(name: string, signal?: AbortSignal): Promise<Paired> {
    const value = await this.json('POST', '/v1/clients', { body: { name }, signal, timeout: APPROVAL_TIMEOUT });
    if (
      !isRecord(value) ||
      typeof value.id !== 'string' ||
      typeof value.token !== 'string' ||
      !value.token ||
      typeof value.expiresAt !== 'number'
    ) {
      throw new ConnectError('bad-response');
    }
    return { id: value.id, token: value.token, expiresAt: value.expiresAt };
  }

  /** Gives up this client's token. */
  async forget(): Promise<void> {
    await this.call('DELETE', '/v1/clients/self');
  }

  /** Names only, never values. */
  async items(): Promise<ItemRef[]> {
    const value = await this.json('GET', '/v1/items');
    if (!isRecord(value) || !Array.isArray(value.items) || !value.items.every(isItem)) {
      throw new ConnectError('bad-response');
    }
    return value.items.map(({ vault, item, itemId, type, fields }) => ({
      vault,
      item,
      itemId,
      type,
      fields: fields.map(({ name, secret }) => ({ name, secret })),
    }));
  }

  private async json(method: string, path: string, call: Call = {}): Promise<unknown> {
    const { text } = await this.call(method, path, call);
    try {
      return JSON.parse(text);
    } catch {
      throw new ConnectError('bad-response');
    }
  }

  private async call(method: string, path: string, call: Call = {}): Promise<Reply> {
    const reply = await this.send(method, path, call);
    if (reply.status >= 200 && reply.status < 300) {
      return reply;
    }
    throw refusal(reply);
  }

  private send(method: string, path: string, { body, signal, timeout = REQUEST_TIMEOUT }: Call): Promise<Reply> {
    const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
    const { endpoint, token } = this;
    const headers: Record<string, string | number> = {
      Host: endpoint.kind === 'socket' ? 'localhost' : `${endpoint.host}:${endpoint.port}`,
      Connection: 'close',
    };
    if (token) {
      headers.Authorization = `Bearer ${token}`;
    }
    if (payload) {
      headers['Content-Type'] = 'application/json';
      headers['Content-Length'] = payload.length;
    }
    // Always the address itself: `localhost` could resolve to ::1, where Connect never listens.
    const target = endpoint.kind === 'socket' ? { socketPath: endpoint.path } : { host: '127.0.0.1', port: endpoint.port };

    return new Promise((resolve, reject) => {
      // ClientRequest rather than http.request: editors patch http.request to send traffic through
      // the user's proxy, and a bearer token for a local service must not take that route.
      const request = new http.ClientRequest({ ...target, method, path, headers, agent: false, signal }, (response) => {
        const chunks: Buffer[] = [];
        let size = 0;
        response.on('data', (chunk: Buffer) => {
          size += chunk.length;
          if (size > MAX_RESPONSE) {
            request.destroy(new ConnectError('bad-response'));
            return;
          }
          chunks.push(chunk);
        });
        response.on('end', () => {
          if (response.complete) {
            resolve({ status: response.statusCode ?? 0, text: Buffer.concat(chunks).toString('utf8') });
          } else {
            reject(new ConnectError('not-running'));
          }
        });
        response.on('error', (error) => reject(unreachable(error)));
      });
      request.setTimeout(timeout, () => request.destroy(new ConnectError('timed-out')));
      request.on('error', (error) => reject(unreachable(error)));
      request.end(payload);
    });
  }
}

function unreachable(error: Error): ConnectError {
  if (error instanceof ConnectError) {
    return error;
  }
  return new ConnectError(error.name === 'AbortError' ? 'cancelled' : 'not-running', error.message);
}

const BY_STATUS: Record<number, Failure> = {
  400: 'bad-request',
  401: 'unauthorized',
  404: 'not-found',
  423: 'locked',
  429: 'busy',
};

/** The status decides, and the body only tells `denied` from `forbidden`. Not every error has the documented body. */
function refusal({ status, text }: Reply): ConnectError {
  let error: unknown;
  try {
    error = (JSON.parse(text) as { error?: unknown }).error;
  } catch {
    error = undefined;
  }
  const code = isRecord(error) ? error.code : undefined;
  const message = isRecord(error) && typeof error.message === 'string' ? error.message : '';
  const failure = status === 403 ? (code === 'denied' ? 'denied' : 'forbidden') : (BY_STATUS[status] ?? 'failed');
  return new ConnectError(failure, message, status);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function isField(value: unknown): value is ItemField {
  return isRecord(value) && typeof value.name === 'string' && typeof value.secret === 'boolean';
}

function isItem(value: unknown): value is ItemRef {
  return (
    isRecord(value) &&
    typeof value.vault === 'string' &&
    typeof value.item === 'string' &&
    typeof value.itemId === 'string' &&
    typeof value.type === 'string' &&
    Array.isArray(value.fields) &&
    value.fields.every(isField)
  );
}
