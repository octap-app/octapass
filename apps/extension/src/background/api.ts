// The sync API calls the engine has no method for: registration when turning a local vault into an
// account, and `POST /v1/batch` for imports and the first upload. Authenticated calls borrow the
// engine's access token, which the engine's own fetch (TokenTap) remembers as it goes by; see plan
// 13, History, for the engine API that would make this unnecessary.

import type { EncryptedItem } from '@octapass/core';
import { VaultError, type VaultErrorCode } from '@octapass/vault-client';

const PROBLEM_BASE = 'https://octap.app/problems/';
const ERRORS: Record<string, VaultErrorCode> = {
  'account-exists': 'emailTaken',
  'invalid-verification-code': 'invalidVerificationCode',
  'signups-closed': 'signupsClosed',
  'invite-required': 'signupsClosed',
  'rate-limited': 'rateLimited',
  unauthorized: 'sessionExpired',
  forbidden: 'readOnlyVault',
};

/** Wraps the engine's fetch and keeps the last bearer token it sent to each server. */
export class TokenTap {
  private readonly tokens = new Map<string, string>();

  readonly fetch: typeof fetch = (input, init) => {
    const authorization = new Headers(init?.headers).get('Authorization');
    if (authorization?.startsWith('Bearer ')) {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
      this.tokens.set(new URL(url).origin, authorization.slice('Bearer '.length));
    }
    return fetch(input, init);
  };

  token(serverUrl: string): string | undefined {
    return this.tokens.get(new URL(serverUrl).origin);
  }
}

export async function apiRequest<T>(serverUrl: string, method: string, path: string, options: { body?: unknown; token?: string } = {}): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${serverUrl}${path}`, {
      method,
      headers: {
        Accept: 'application/json, application/problem+json',
        ...(options.body === undefined ? {} : { 'Content-Type': 'application/json' }),
        ...(options.token ? { Authorization: `Bearer ${options.token}` } : {}),
      },
      ...(options.body === undefined ? {} : { body: JSON.stringify(options.body) }),
      credentials: 'omit',
      referrerPolicy: 'no-referrer',
    });
  } catch {
    throw new VaultError('serverUnreachable');
  }
  if (!response.ok) {
    const body = (await response.json().catch(() => ({}))) as { type?: string; detail?: string };
    const type = body.type?.startsWith(PROBLEM_BASE) ? body.type.slice(PROBLEM_BASE.length) : '';
    throw new VaultError(ERRORS[type] ?? 'serverError', body.detail ?? `HTTP ${response.status}`);
  }
  return response.status === 204 ? (undefined as T) : ((await response.json()) as T);
}

export interface PutOperation {
  vaultId: string;
  itemId: string;
  item: EncryptedItem;
}

interface BatchResult {
  itemId: string;
  status: number;
  revision?: number;
}

/** Most operations per request the server takes (sync API: 1,000 and 16 MiB). */
const BATCH_SIZE = 500;

/**
 * Creates items with `POST /v1/batch`, a few hundred per request (each one atomic per vault).
 * Returns how many the server took. `token` is asked again for each request, after a refresh.
 */
export async function putItems(serverUrl: string, token: () => Promise<string>, operations: PutOperation[]): Promise<number> {
  let created = 0;
  for (let start = 0; start < operations.length; start += BATCH_SIZE) {
    const chunk = operations.slice(start, start + BATCH_SIZE).map((op) => ({ op: 'put', ...op }));
    const { results } = await apiRequest<{ results: BatchResult[] }>(serverUrl, 'POST', '/v1/batch', { token: await token(), body: { operations: chunk } });
    created += results.filter((r) => r.status >= 200 && r.status < 300).length;
  }
  return created;
}
