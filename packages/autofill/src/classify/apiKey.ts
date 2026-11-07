// Recognising API keys and the fields that take them. Pure text functions: nothing here touches the
// page, and nothing leaves the device. A value is an API key only if the whole of it has a known shape,
// or if the field says it takes a key and the value looks random. Prose never gets that far.

import { normalize } from '../dom/text';

export const API_KEY_SERVICES = {
  github: 'GitHub',
  stripe: 'Stripe',
  aws: 'AWS',
  slack: 'Slack',
  npm: 'npm',
  anthropic: 'Anthropic',
  openai: 'OpenAI',
  gitlab: 'GitLab',
  sendgrid: 'SendGrid',
  google: 'Google',
  jwt: 'JWT',
  'octapass-service-account': 'Octa Pass service account',
  'octapass-connect': 'Octa Pass Connect',
} as const;

/** `generic`: no known shape, but a key or token field and a random-looking value. */
export type ApiKeyKind = keyof typeof API_KEY_SERVICES | 'generic';

/** Longer than any key people paste; a bigger paste isn't one. */
const MAX_LENGTH = 8192;
/** Fewer different characters than this is a placeholder (`sk-xxxxxxxx…`), not a key. */
const MIN_DISTINCT = 7;

function hasDigitAndUpper(token: string): boolean {
  return /\d/.test(token) && /[A-Z]/.test(token);
}

function base64urlJson(part: string): unknown {
  try {
    return JSON.parse(atob(part.replaceAll('-', '+').replaceAll('_', '/')));
  } catch {
    return undefined;
  }
}

/** Three parts is common (`1.2.3`, file names): only a JSON header naming an algorithm makes a JWT. */
function hasJwtHeader(token: string): boolean {
  const header = base64urlJson(token.split('.')[0]!);
  return typeof header === 'object' && header !== null && typeof (header as { alg?: unknown }).alg === 'string';
}

/** In order: `sk-ant-…` is also a shape OpenAI's rule would take. */
const SHAPES: { kind: Exclude<ApiKeyKind, 'generic'>; shape: RegExp; check?: (token: string) => boolean }[] = [
  { kind: 'github', shape: /^(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})$/ },
  { kind: 'stripe', shape: /^(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}$/ },
  { kind: 'aws', shape: /^A(?:KIA|SIA)[A-Z0-9]{16}$/ },
  { kind: 'slack', shape: /^xox[abeoprs]-[A-Za-z0-9-]{10,}$/ },
  { kind: 'npm', shape: /^npm_[A-Za-z0-9]{36,}$/ },
  { kind: 'anthropic', shape: /^sk-ant-[A-Za-z0-9_-]{20,}$/ },
  // `sk-` alone also starts ordinary slugs, so this one needs to look generated.
  { kind: 'openai', shape: /^sk-[A-Za-z0-9_-]{32,}$/, check: hasDigitAndUpper },
  { kind: 'gitlab', shape: /^glpat-[A-Za-z0-9_.-]{20,}$/ },
  { kind: 'sendgrid', shape: /^SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}$/ },
  { kind: 'google', shape: /^AIza[A-Za-z0-9_-]{35}$/ },
  { kind: 'jwt', shape: /^eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{16,}$/, check: hasJwtHeader },
  { kind: 'octapass-service-account', shape: /^opsa1_[A-Za-z0-9_-]{32,}$/ },
  { kind: 'octapass-connect', shape: /^opc1_[A-Za-z0-9_-]{16,}$/ },
];

/** Bits per character. */
function entropy(token: string): number {
  const counts = new Map<string, number>();
  for (const character of token) counts.set(character, (counts.get(character) ?? 0) + 1);
  let bits = 0;
  for (const count of counts.values()) {
    const share = count / token.length;
    bits -= share * Math.log2(share);
  }
  return bits;
}

/** Mostly dictionary-looking parts: `my-project-2024-staging-env`, `test_token_value_123`. */
function isWordy(token: string): boolean {
  const parts = token.split(/[-_.]/);
  const letters = parts.filter((part) => /^[A-Za-z]+$/.test(part)).reduce((sum, part) => sum + part.length, 0);
  return letters * 2 > token.length;
}

/** Bits per character. Random hex tops out at 4 and short samples land near 3.4, UUIDs included. */
const MIN_ENTROPY = 3.3;

/** Random enough to be a key: no URLs, dates or words. */
function looksRandom(token: string): boolean {
  if (token.length < 24 || token.length > 1024) return false;
  if (!/^[A-Za-z0-9_+/=.~-]+$/.test(token)) return false;
  if (!/[A-Za-z]/.test(token) || !/\d/.test(token)) return false;
  return entropy(token) >= MIN_ENTROPY && !isWordy(token);
}

/** The one token a paste holds, without a leading `Bearer `, or undefined for anything else. */
export function pastedToken(text: string): string | undefined {
  if (!text || text.length > MAX_LENGTH) return undefined;
  const token = text.trim().replace(/^(?:bearer|token)\s+/i, '');
  return token && !/\s/.test(token) ? token : undefined;
}

/** What kind of key `token` is. `hinted`: the field says it takes a key, the only way `generic` is given. */
export function recognizeApiKey(token: string, hinted: boolean): ApiKeyKind | undefined {
  if (new Set(token).size < MIN_DISTINCT) return undefined;
  const known = SHAPES.find(({ shape, check }) => shape.test(token) && (check?.(token) ?? true));
  if (known) return known.kind;
  return hinted && looksRandom(token) ? 'generic' : undefined;
}

const BOUNDARY_START = '(?<![\\p{L}\\p{N}])';
const BOUNDARY_END = '(?![\\p{L}\\p{N}])';
const SEP = '[ _-]?';

/** What marks a field as taking a key. `key` alone doesn't: it's a licence key, a search key, a map key. */
const NAMED = new RegExp(
  `${BOUNDARY_START}(?:api${SEP}(?:keys?|tokens?|secrets?)|secret${SEP}(?:access${SEP})?keys?|(?:access|auth|personal${SEP}access)${SEP}tokens?|client${SEP}secrets?|bearer|authorization|tokens?|secrets?)${BOUNDARY_END}`,
  'u',
);
const NAMED_ELSEWHERE = /مفتاح api|رمز api|رمز الوصول|clave (?:de )?api|cle (?:d['’ ])?api|chave (?:de )?api|api[ -]?schlussel|api[ -]?ключ|ключ api|токен|令牌|トークン|api ?キー/u;

/**
 * Mentions a token but isn't one: fields about the token ('Token name', 'Secret ID', 'Token URL') and
 * tokens from other features (2FA, password resets, forgery protection).
 */
const NOT_THE_VALUE = new RegExp(
  [
    'csrf|xsrf|captcha|authenticity|verification|verify|one[ _-]?time|otp|totp|2fa|mfa|recovery|backup|reset|invit|session|public|publishable|payment|card|cvv|security (?:question|answer)|secret (?:question|answer|santa|word|phrase)',
    `${BOUNDARY_START}(?:names?|labels?|titles?|desc|descriptions?|notes?|memo|expir\\w*|ttl|lifetime|duration|scopes?|permissions?|ids?|urls?|uris?|endpoints?|prefix|types?|kinds?|counts?|limits?|hash|usage|owner|codes?|numbers?)${BOUNDARY_END}`,
  ].join('|'),
  'u',
);

/**
 * What normalized text says about a field: true when it marks it as taking a key or token, false when
 * it mentions one but is about something else, undefined when it has nothing to say.
 */
export function credentialHint(text: string): boolean | undefined {
  const folded = normalize(text);
  if (!NAMED.test(folded) && !NAMED_ELSEWHERE.test(folded)) return undefined;
  return !NOT_THE_VALUE.test(folded);
}
