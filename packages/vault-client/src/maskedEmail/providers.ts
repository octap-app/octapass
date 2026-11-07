// The masked email providers' APIs (plan 06, Phase A). Each call goes from this device straight to
// the provider with the user's own token; the Octa Pass server is never in the path.

import { VaultError, type VaultErrorCode } from '../errors';
import type { MaskedAlias, MaskedEmailProviderDetails, MaskedEmailProviderId } from '../types';

export interface HttpRequest {
  url: string;
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  headers: Record<string, string>;
  body?: string;
}

export interface HttpResponse {
  status: number;
  /** Lower-case names. */
  headers: Record<string, string>;
  body: string;
}

/** Makes one request. Rejects only when nothing came back (offline, or blocked by the browser). */
export type MaskedEmailHttp = (request: HttpRequest) => Promise<HttpResponse>;

/** `fetch`, without cookies or a referrer: the token is the only credential sent. */
export function fetchHttp(fetchImpl?: typeof fetch): MaskedEmailHttp {
  // Wrapped so a bare `fetch` isn't called with the wrong `this`, which browsers reject.
  const send = fetchImpl ?? ((input: RequestInfo | URL, init?: RequestInit) => fetch(input, init));
  return async ({ url, method, headers, body }) => {
    const response = await send(url, { method, headers, body, credentials: 'omit', referrerPolicy: 'no-referrer', cache: 'no-store' });
    const out: Record<string, string> = {};
    response.headers.forEach((value, name) => (out[name.toLowerCase()] = value));
    return { status: response.status, headers: out, body: await response.text() };
  };
}

export interface ProviderInfo {
  id: MaskedEmailProviderId;
  name: string;
  /**
   * Answers CORS requests, so a web page can call it. The others work only from the extension and
   * the apps (checked 2026-10-23; see docs/features/masked-email.md).
   */
  cors: boolean;
  /** Where the user makes an API token. */
  tokenUrl: string;
  /** The API's default origin; set for providers that can be self-hosted. */
  defaultBaseUrl?: string;
  /** New aliases need a domain (addy.io, Forward Email). */
  needsDomain: boolean;
}

export const MASKED_EMAIL_PROVIDERS: readonly ProviderInfo[] = [
  { id: 'simplelogin', name: 'SimpleLogin', cors: true, tokenUrl: 'https://app.simplelogin.io/dashboard/api_key', defaultBaseUrl: 'https://app.simplelogin.io', needsDomain: false },
  { id: 'addy', name: 'addy.io', cors: true, tokenUrl: 'https://app.addy.io/settings/api', defaultBaseUrl: 'https://app.addy.io', needsDomain: true },
  { id: 'firefoxRelay', name: 'Firefox Relay', cors: false, tokenUrl: 'https://relay.firefox.com/accounts/settings/', needsDomain: false },
  { id: 'fastmail', name: 'Fastmail', cors: true, tokenUrl: 'https://app.fastmail.com/settings/security/tokens', needsDomain: false },
  { id: 'duckduckgo', name: 'DuckDuckGo', cors: false, tokenUrl: 'https://duckduckgo.com/email/settings/autofill', needsDomain: false },
  { id: 'forwardEmail', name: 'Forward Email', cors: true, tokenUrl: 'https://forwardemail.net/my-account/security', needsDomain: true },
];

/** The providers' API hosts, which the apps call natively. Matches `PROVIDER_API_HOSTS` in octapass-core. */
export const PROVIDER_API_HOSTS: readonly string[] = ['app.simplelogin.io', 'app.addy.io', 'relay.firefox.com', 'api.fastmail.com', 'quack.duckduckgo.com', 'api.forwardemail.net'];

export function providerInfo(id: MaskedEmailProviderId): ProviderInfo {
  const info = MASKED_EMAIL_PROVIDERS.find((p) => p.id === id);
  if (!info) throw new VaultError('maskedEmailFailed', `Unknown provider: ${id}`);
  return info;
}

/** A provider call failed. `retryAfter` (seconds) comes with `maskedEmailRateLimited` when the provider said. */
export class MaskedEmailError extends VaultError {
  readonly retryAfter?: number;

  constructor(code: VaultErrorCode, message?: string, retryAfter?: number) {
    super(code, message);
    if (retryAfter !== undefined) this.retryAfter = retryAfter;
  }
}

/** A self-hosted server must use HTTPS, except on this computer (for development and tests). */
export function checkBaseUrl(url: string): string {
  let parsed: URL;
  try {
    parsed = new URL(url.trim());
  } catch {
    throw new VaultError('insecureServerUrl');
  }
  const local = parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1' || parsed.hostname === '[::1]';
  if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && local)) throw new VaultError('insecureServerUrl');
  return parsed.origin + parsed.pathname.replace(/\/+$/, '');
}

/** What the new alias is for: the site's domain, and its origin for providers that take one. */
export interface AliasFor {
  domain: string;
  origin: string;
}

type Config = Pick<MaskedEmailProviderDetails, 'token' | 'baseUrl' | 'domain'>;

const JSON_HEADERS = { 'Content-Type': 'application/json', Accept: 'application/json' };
const FASTMAIL_SESSION = 'https://api.fastmail.com/jmap/session';
const FASTMAIL_CAPABILITY = 'https://www.fastmail.com/dev/maskedemail';

function parse(body: string): unknown {
  try {
    return JSON.parse(body);
  } catch {
    return undefined;
  }
}

/** The provider's own words about an error, from the usual JSON shapes. */
function providerMessage(body: string): string | undefined {
  const json = parse(body) as Record<string, unknown> | undefined;
  const text = json && [json.error, json.message, json.detail, json.description].find((v) => typeof v === 'string' && v.trim());
  return typeof text === 'string' ? text.trim().slice(0, 200) : undefined;
}

function retryAfter(headers: Record<string, string>): number | undefined {
  const value = headers['retry-after'];
  if (!value) return undefined;
  const seconds = Number(value);
  if (Number.isFinite(seconds)) return Math.max(0, Math.round(seconds));
  const at = Date.parse(value);
  return Number.isNaN(at) ? undefined : Math.max(0, Math.round((at - Date.now()) / 1000));
}

/** The provider's answer, once errors are thrown. `goneIsFine` accepts 404: what was asked for is already so. */
async function answer(http: MaskedEmailHttp, request: HttpRequest, goneIsFine = false): Promise<string> {
  let response: HttpResponse;
  try {
    response = await http(request);
  } catch {
    throw new MaskedEmailError('maskedEmailUnreachable');
  }
  const { status, headers, body } = response;
  if (status === 401 || status === 403) throw new MaskedEmailError('maskedEmailToken', providerMessage(body));
  if (status === 429) throw new MaskedEmailError('maskedEmailRateLimited', providerMessage(body), retryAfter(headers));
  if (status === 404 && goneIsFine) return '';
  if (status < 200 || status > 299) throw new MaskedEmailError('maskedEmailFailed', providerMessage(body) ?? `HTTP ${status}`);
  return body;
}

async function send(http: MaskedEmailHttp, request: HttpRequest): Promise<unknown> {
  const body = await answer(http, request);
  const json = parse(body);
  if (json === undefined) throw new MaskedEmailError('maskedEmailFailed', 'The provider sent an answer Octa Pass could not read.');
  return json;
}

function invalid(): never {
  throw new MaskedEmailError('maskedEmailFailed', 'The provider sent an answer Octa Pass could not read.');
}

function str(value: unknown): string | undefined {
  return typeof value === 'string' && value ? value : typeof value === 'number' ? String(value) : undefined;
}

type Create = (http: MaskedEmailHttp, config: Config, site: AliasFor) => Promise<Omit<MaskedAlias, 'provider'>>;

const simplelogin: Create = async (http, { token, baseUrl }, site) => {
  const base = baseUrl ?? providerInfo('simplelogin').defaultBaseUrl!;
  const json = (await send(http, {
    url: `${base}/api/alias/random/new?hostname=${encodeURIComponent(site.domain)}`,
    method: 'POST',
    headers: { ...JSON_HEADERS, Authentication: token },
    body: JSON.stringify({ note: site.domain }),
  })) as { alias?: unknown; id?: unknown };
  const email = str(json.alias);
  return email ? { email, aliasId: str(json.id) ?? email } : invalid();
};

const addy: Create = async (http, { token, baseUrl, domain }, site) => {
  const base = baseUrl ?? providerInfo('addy').defaultBaseUrl!;
  const json = (await send(http, {
    url: `${base}/api/v1/aliases`,
    method: 'POST',
    headers: { ...JSON_HEADERS, Authorization: `Bearer ${token}`, 'X-Requested-With': 'XMLHttpRequest' },
    body: JSON.stringify({ domain, description: site.domain }),
  })) as { data?: { id?: unknown; email?: unknown } };
  const email = str(json.data?.email);
  return email ? { email, aliasId: str(json.data?.id) ?? email } : invalid();
};

const firefoxRelay: Create = async (http, { token }, site) => {
  const json = (await send(http, {
    url: 'https://relay.firefox.com/api/v1/relayaddresses/',
    method: 'POST',
    headers: { ...JSON_HEADERS, Authorization: `Token ${token}` },
    body: JSON.stringify({ enabled: true, generated_for: site.domain, description: site.domain }),
  })) as { id?: unknown; full_address?: unknown };
  const email = str(json.full_address);
  return email ? { email, aliasId: str(json.id) ?? email } : invalid();
};

/** The JMAP session names the account that has masked email and where to call. */
async function fastmailSession(http: MaskedEmailHttp, token: string): Promise<{ accountId: string; apiUrl: string; auth: { Authorization: string } }> {
  const auth = { Authorization: `Bearer ${token}` };
  const session = (await send(http, { url: FASTMAIL_SESSION, method: 'GET', headers: { ...auth, Accept: 'application/json' } })) as {
    apiUrl?: unknown;
    primaryAccounts?: Record<string, unknown>;
  };
  const accountId = str(session.primaryAccounts?.[FASTMAIL_CAPABILITY]);
  const apiUrl = str(session.apiUrl);
  // A token without the Masked Email scope gets a session without the capability.
  if (!accountId) throw new MaskedEmailError('maskedEmailToken', 'This token has no access to Masked Email.');
  if (!apiUrl?.startsWith('https://')) invalid();
  return { accountId, apiUrl: apiUrl as string, auth };
}

/** JMAP: `MaskedEmail/set` creates one. */
const fastmail: Create = async (http, { token }, site) => {
  const { accountId, apiUrl, auth } = await fastmailSession(http, token);
  const json = (await send(http, {
    url: apiUrl,
    method: 'POST',
    headers: { ...JSON_HEADERS, ...auth },
    body: JSON.stringify({
      using: ['urn:ietf:params:jmap:core', FASTMAIL_CAPABILITY],
      methodCalls: [['MaskedEmail/set', { accountId, create: { octapass: { state: 'enabled', description: site.domain, forDomain: site.origin } } }, '0']],
    }),
  })) as { methodResponses?: [string, Record<string, unknown>, string][] };
  const [name, result] = json.methodResponses?.[0] ?? [];
  if (name === 'error') throw new MaskedEmailError('maskedEmailFailed', str(result?.description) ?? str(result?.type));
  const created = (result?.created as Record<string, { id?: unknown; email?: unknown }> | undefined)?.octapass;
  const refused = (result?.notCreated as Record<string, { description?: unknown; type?: unknown }> | undefined)?.octapass;
  if (refused) throw new MaskedEmailError('maskedEmailFailed', str(refused.description) ?? str(refused.type));
  const email = str(created?.email);
  return email ? { email, aliasId: str(created?.id) ?? email } : invalid();
};

/** DuckDuckGo's private address API: no description, no id, just a new address on duck.com. */
const duckduckgo: Create = async (http, { token }) => {
  const json = (await send(http, {
    url: 'https://quack.duckduckgo.com/api/email/addresses',
    method: 'POST',
    headers: { Accept: 'application/json', Authorization: `Bearer ${token}` },
  })) as { address?: unknown };
  const local = str(json.address);
  if (!local || !/^[a-z0-9._-]+$/i.test(local)) invalid();
  const email = `${local}@duck.com`;
  return { email, aliasId: email };
};

/** Basic auth with the token as the user name; leaving out the alias name gets a random one. */
const forwardEmail: Create = async (http, { token, domain }, site) => {
  const json = (await send(http, {
    url: `https://api.forwardemail.net/v1/domains/${encodeURIComponent(domain ?? '')}/aliases`,
    method: 'POST',
    headers: { ...JSON_HEADERS, Authorization: `Basic ${btoa(`${token}:`)}` },
    body: JSON.stringify({ description: site.domain, labels: site.domain, is_enabled: true }),
  })) as { id?: unknown; name?: unknown; domain?: { name?: unknown } };
  const name = str(json.name);
  const email = name && `${name}@${str(json.domain?.name) ?? domain}`;
  return email ? { email, aliasId: str(json.id) ?? email } : invalid();
};

const CREATE: Record<MaskedEmailProviderId, Create> = { simplelogin, addy, firefoxRelay, fastmail, duckduckgo, forwardEmail };

/**
 * What can be done to an alias already made. Providers without a call for it (DuckDuckGo) and
 * aliases with no id of their own can only be managed on the provider's site.
 */
export function canManageAlias(provider: MaskedEmailProviderId, aliasId: string, email: string): boolean {
  return provider !== 'duckduckgo' && aliasId !== '' && aliasId !== email;
}

export type AliasAction = 'enable' | 'disable' | 'delete';

type Act = (http: MaskedEmailHttp, config: Config, aliasId: string, action: AliasAction) => Promise<void>;

/** SimpleLogin only toggles, so the alias's state comes first and a repeat changes nothing. */
const simpleloginAction: Act = async (http, { token, baseUrl }, aliasId, action) => {
  const base = baseUrl ?? providerInfo('simplelogin').defaultBaseUrl!;
  const headers = { ...JSON_HEADERS, Authentication: token };
  const url = `${base}/api/aliases/${encodeURIComponent(aliasId)}`;
  if (action === 'delete') {
    await answer(http, { url, method: 'DELETE', headers }, true);
    return;
  }
  const alias = (await send(http, { url, method: 'GET', headers })) as { enabled?: unknown };
  if (typeof alias.enabled !== 'boolean') invalid();
  if (alias.enabled !== (action === 'enable')) await answer(http, { url: `${url}/toggle`, method: 'POST', headers });
};

const addyAction: Act = async (http, { token, baseUrl }, aliasId, action) => {
  const base = baseUrl ?? providerInfo('addy').defaultBaseUrl!;
  const headers = { ...JSON_HEADERS, Authorization: `Bearer ${token}`, 'X-Requested-With': 'XMLHttpRequest' };
  const id = encodeURIComponent(aliasId);
  if (action === 'delete') await answer(http, { url: `${base}/api/v1/aliases/${id}`, method: 'DELETE', headers }, true);
  else if (action === 'disable') await answer(http, { url: `${base}/api/v1/active-aliases/${id}`, method: 'DELETE', headers });
  else await answer(http, { url: `${base}/api/v1/active-aliases`, method: 'POST', headers, body: JSON.stringify({ id: aliasId }) });
};

const firefoxRelayAction: Act = async (http, { token }, aliasId, action) => {
  const url = `https://relay.firefox.com/api/v1/relayaddresses/${encodeURIComponent(aliasId)}/`;
  const headers = { ...JSON_HEADERS, Authorization: `Token ${token}` };
  if (action === 'delete') await answer(http, { url, method: 'DELETE', headers }, true);
  else await answer(http, { url, method: 'PATCH', headers, body: JSON.stringify({ enabled: action === 'enable' }) });
};

/** JMAP again: an alias's `state` is `enabled`, `disabled` or `deleted`. */
const fastmailAction: Act = async (http, { token }, aliasId, action) => {
  const { accountId, apiUrl, auth } = await fastmailSession(http, token);
  const state = { enable: 'enabled', disable: 'disabled', delete: 'deleted' }[action];
  const json = (await send(http, {
    url: apiUrl,
    method: 'POST',
    headers: { ...JSON_HEADERS, ...auth },
    body: JSON.stringify({
      using: ['urn:ietf:params:jmap:core', FASTMAIL_CAPABILITY],
      methodCalls: [['MaskedEmail/set', { accountId, update: { [aliasId]: { state } } }, '0']],
    }),
  })) as { methodResponses?: [string, Record<string, unknown>, string][] };
  const [name, result] = json.methodResponses?.[0] ?? [];
  if (name === 'error') throw new MaskedEmailError('maskedEmailFailed', str(result?.description) ?? str(result?.type));
  const refused = (result?.notUpdated as Record<string, { description?: unknown; type?: unknown }> | undefined)?.[aliasId];
  if (refused && !(action === 'delete' && refused.type === 'notFound')) throw new MaskedEmailError('maskedEmailFailed', str(refused.description) ?? str(refused.type));
};

const forwardEmailAction: Act = async (http, { token, domain }, aliasId, action) => {
  const url = `https://api.forwardemail.net/v1/domains/${encodeURIComponent(domain ?? '')}/aliases/${encodeURIComponent(aliasId)}`;
  const headers = { ...JSON_HEADERS, Authorization: `Basic ${btoa(`${token}:`)}` };
  if (action === 'delete') await answer(http, { url, method: 'DELETE', headers }, true);
  else await answer(http, { url, method: 'PUT', headers, body: JSON.stringify({ is_enabled: action === 'enable' }) });
};

const ACT: Partial<Record<MaskedEmailProviderId, Act>> = {
  simplelogin: simpleloginAction,
  addy: addyAction,
  firefoxRelay: firefoxRelayAction,
  fastmail: fastmailAction,
  forwardEmail: forwardEmailAction,
};

/** Turns an alias on or off, or deletes it, at the provider. Deleting one that's already gone succeeds. */
export async function changeProviderAlias(http: MaskedEmailHttp, details: Pick<MaskedEmailProviderDetails, 'provider' | 'token' | 'baseUrl' | 'domain'>, aliasId: string, action: AliasAction): Promise<void> {
  const act = ACT[details.provider];
  if (!act) throw new MaskedEmailError('maskedEmailFailed', `${providerInfo(details.provider).name} has no API for this.`);
  const config: Config = { token: details.token, ...(details.domain ? { domain: details.domain } : {}), ...(details.baseUrl ? { baseUrl: checkBaseUrl(details.baseUrl) } : {}) };
  await act(http, config, aliasId, action);
}

/** Asks the provider for a new alias for `site`. Throws a `MaskedEmailError`. */
export async function createProviderAlias(http: MaskedEmailHttp, details: Pick<MaskedEmailProviderDetails, 'provider' | 'token' | 'baseUrl' | 'domain'>, site: AliasFor): Promise<MaskedAlias> {
  const info = providerInfo(details.provider);
  if (info.needsDomain && !details.domain) throw new MaskedEmailError('maskedEmailFailed', `${info.name} needs a domain for new aliases.`);
  const config: Config = { token: details.token, ...(details.domain ? { domain: details.domain } : {}), ...(details.baseUrl ? { baseUrl: checkBaseUrl(details.baseUrl) } : {}) };
  const alias = await CREATE[info.id](http, config, site);
  return { ...alias, provider: info.id };
}
