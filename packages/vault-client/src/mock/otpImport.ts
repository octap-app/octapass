// The demo's stand-in for the core's authenticator import and QR reading: `otpauth://totp` links
// only (no Google Authenticator exports, no backups), matched to logins by title. Enough for UI
// work and the web vault's tests; the real apps use crates/octapass-core.

import type { ItemSummary, QrScan } from '../types';

export interface MockCode {
  uri: string;
  title: string;
  issuer?: string;
  account?: string;
  /** The login it joins, matched by issuer and title. */
  loginId?: string;
}

/** One code per `otpauth://totp/…` line; other lines are skipped. */
export function parseOtpLinks(text: string, logins: ItemSummary[]): { codes: MockCode[]; skipped: number } {
  const codes: MockCode[] = [];
  let skipped = 0;
  const taken = new Set<string>();
  for (const line of text.split(/\r?\n/).map((l) => l.trim())) {
    if (!line) continue;
    const parsed = parseLink(line);
    if (!parsed) {
      skipped++;
      continue;
    }
    const key = (s: string) => s.toLowerCase().replace(/[^\p{L}\p{N}]/gu, '');
    const match = parsed.issuer
      ? logins.find((l) => !l.hasTotp && !taken.has(l.id) && (l.type === 'login' || l.type === 'password') && key(l.title) === key(parsed.issuer!))
      : undefined;
    if (match) taken.add(match.id);
    codes.push({ ...parsed, ...(match ? { loginId: match.id } : {}) });
  }
  return { codes, skipped };
}

function parseLink(text: string): Omit<MockCode, 'loginId'> | undefined {
  if (!/^otpauth:\/\/totp\//i.test(text)) return undefined;
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    return undefined;
  }
  if (!url.searchParams.get('secret')) return undefined;
  const label = decodeURIComponent(url.pathname.replace(/^\/+/, ''));
  const [labelIssuer, account] = label.includes(':') ? label.split(/:(.*)/, 2) : [undefined, label];
  const issuer = url.searchParams.get('issuer') || labelIssuer?.trim() || undefined;
  return {
    uri: text,
    title: issuer || account?.trim() || 'One-time code',
    ...(issuer ? { issuer } : {}),
    ...(account?.trim() ? { account: account.trim() } : {}),
  };
}

export function summarizeLinks(texts: string[]): QrScan {
  const scan: QrScan = { codes: [], incomplete: [], other: 0, broken: 0 };
  for (const text of new Set(texts.map((t) => t.trim()).filter(Boolean))) {
    const parsed = parseLink(text);
    if (parsed) {
      if (!scan.codes.some((c) => c.uri === parsed.uri)) {
        scan.codes.push({ uri: parsed.uri, ...(parsed.issuer ? { issuer: parsed.issuer } : {}), ...(parsed.account ? { account: parsed.account } : {}), counterBased: false });
      }
    } else if (/^otpauth/i.test(text)) scan.broken++;
    else scan.other++;
  }
  return scan;
}

/**
 * The demo can't decode pictures: an "image" whose bytes are text lines holds those lines as its
 * QR codes (what the tests pass). Real images hold none.
 */
export async function readMockQrCodes(image: Blob): Promise<string[]> {
  const text = await image.text();
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x08]/.test(text)) return [];
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
}
