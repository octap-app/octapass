// A small client for the sync API (docs/developers/sync-api.md): JSON in and out, problem+json
// errors, bearer tokens with one refresh on 401, and Retry-After on 429.

import { VaultError, type VaultErrorCode } from '../errors';

const PROBLEM_BASE = 'https://octap.app/problems/';

/** An error answer from the server, before it's turned into a `VaultError`. */
export class ApiProblem extends Error {
  constructor(
    readonly status: number,
    /** The part of the problem `type` after `…/problems/`, e.g. `conflict`. */
    readonly type: string,
    readonly body: Record<string, unknown>,
    /** Seconds from `Retry-After`, when the server sent one. */
    readonly retryAfter?: number,
  ) {
    super(typeof body.detail === 'string' ? body.detail : type);
    this.name = 'ApiProblem';
  }
}

const VAULT_ERRORS: Record<string, VaultErrorCode> = {
  'login-failed': 'invalidCredentials',
  'account-exists': 'emailTaken',
  'invalid-verification-code': 'invalidVerificationCode',
  'signups-closed': 'signupsClosed',
  'invite-required': 'signupsClosed',
  'not-found': 'notFound',
  forbidden: 'readOnlyVault',
  'rate-limited': 'rateLimited',
  'account-deleted': 'accountDeleted',
  unauthorized: 'sessionExpired',
  'reauth-required': 'reauthRequired',
  'already-exists': 'alreadyExists',
  'family-full': 'familyFull',
  'quota-exceeded': 'quotaExceeded',
  'payload-too-large': 'fileTooLarge',
  'invalid-second-factor': 'invalidTwoStepCode',
  'sso-pending': 'ssoPending',
  'sso-config': 'ssoConfig',
  'org-policy': 'orgPolicy',
  'org-vault-orphaned': 'orgVaultOrphaned',
};

/** What the UI should say about a server answer. Problems it can't act on become `serverError`. */
export function toVaultError(error: unknown): unknown {
  if (!(error instanceof ApiProblem)) return error;
  return new VaultError(VAULT_ERRORS[error.type] ?? 'serverError', error.message);
}

export interface HttpOptions {
  baseUrl: string;
  fetch?: typeof fetch;
  /** The current access token, if any. */
  accessToken: () => string | undefined;
  /** Gets a new access token. Rejects when the session can't be refreshed. */
  refresh: () => Promise<void>;
  /** The server says the account behind this token was deleted. */
  onAccountDeleted: () => Promise<void>;
  /** Longest `Retry-After` worth waiting for before giving up with `rateLimited`. */
  maxRetryWaitMs?: number;
  sleep?: (ms: number) => Promise<void>;
}

export interface RequestOptions {
  body?: unknown;
  /** Sent as-is, as `application/octet-stream`, instead of a JSON `body`. */
  binary?: Blob;
  /** Resolve with the `Response` itself, unread, for streaming downloads. */
  raw?: boolean;
  headers?: Record<string, string>;
  /** Send the access token (default true). */
  auth?: boolean;
}

const sleepFor = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

export class HttpClient {
  private readonly fetchImpl: typeof fetch;

  constructor(private readonly options: HttpOptions) {
    // Wrapped so a bare `fetch` isn't called with the wrong `this`, which browsers reject.
    this.fetchImpl = options.fetch ?? ((input, init) => fetch(input, init));
  }

  get baseUrl(): string {
    return this.options.baseUrl;
  }

  async request<T>(method: string, path: string, opts: RequestOptions = {}): Promise<T> {
    const auth = opts.auth ?? true;
    try {
      return await this.send<T>(method, path, opts, auth);
    } catch (error) {
      if (!(error instanceof ApiProblem)) throw error;
      if (error.type === 'account-deleted') {
        await this.options.onAccountDeleted();
        throw error;
      }
      if (auth && error.status === 401 && error.type === 'unauthorized') {
        await this.options.refresh();
        return this.send<T>(method, path, opts, auth);
      }
      if (error.status === 429 && error.retryAfter !== undefined && error.retryAfter * 1000 <= (this.options.maxRetryWaitMs ?? 5000)) {
        await (this.options.sleep ?? sleepFor)(error.retryAfter * 1000);
        return this.send<T>(method, path, opts, auth);
      }
      throw error;
    }
  }

  private async send<T>(method: string, path: string, opts: RequestOptions, auth: boolean): Promise<T> {
    const headers: Record<string, string> = { Accept: 'application/json, application/problem+json', ...opts.headers };
    if (opts.body !== undefined) headers['Content-Type'] = 'application/json';
    if (opts.binary) headers['Content-Type'] = 'application/octet-stream';
    const token = auth ? this.options.accessToken() : undefined;
    if (token) headers.Authorization = `Bearer ${token}`;

    let response: Response;
    try {
      response = await this.fetchImpl(`${this.options.baseUrl}${path}`, {
        method,
        headers,
        // A Blob carries its size, so the request gets the Content-Length uploads need.
        body: opts.binary ?? (opts.body === undefined ? undefined : JSON.stringify(opts.body)),
        credentials: 'omit',
        referrerPolicy: 'no-referrer',
      });
    } catch {
      throw new VaultError('serverUnreachable');
    }
    if (!response.ok) throw await readProblem(response);
    if (opts.raw) return response as T;
    // 202 and 204 answers (invites, deletes) have no body.
    const text = await response.text();
    return (text ? JSON.parse(text) : undefined) as T;
  }
}

async function readProblem(response: Response): Promise<ApiProblem> {
  let body: Record<string, unknown> = {};
  try {
    body = (await response.json()) as Record<string, unknown>;
  } catch {
    // A proxy or load balancer answered with something that isn't problem+json.
  }
  const type = typeof body.type === 'string' && body.type.startsWith(PROBLEM_BASE) ? body.type.slice(PROBLEM_BASE.length) : `http-${response.status}`;
  const retryAfter = Number(response.headers.get('Retry-After'));
  return new ApiProblem(response.status, type, body, Number.isFinite(retryAfter) && retryAfter >= 0 && response.headers.has('Retry-After') ? retryAfter : undefined);
}
