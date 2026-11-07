// Pretend accounts for the mock's sharing screens: every email has the same keys and fingerprint on
// every visit, so a demo can compare fingerprints like the real thing.

import { base64UrlEncode, bytesToHex } from '../tools/encoding';
import type { AccountLookup, Fingerprint } from '../types';

const EMOJI: [string, string][] = [
  ['🐶', 'dog'], ['🐱', 'cat'], ['🦊', 'fox'], ['🐻', 'bear'], ['🐼', 'panda'], ['🐨', 'koala'], ['🐯', 'tiger'], ['🦁', 'lion'],
  ['🐮', 'cow'], ['🐷', 'pig'], ['🐸', 'frog'], ['🐵', 'monkey'], ['🐔', 'chicken'], ['🐧', 'penguin'], ['🦉', 'owl'], ['🐙', 'octopus'],
  ['🦋', 'butterfly'], ['🐢', 'turtle'], ['🐬', 'dolphin'], ['🐳', 'whale'], ['🌵', 'cactus'], ['🌲', 'tree'], ['🍄', 'mushroom'], ['🌻', 'sunflower'],
  ['🌙', 'moon'], ['⭐', 'star'], ['🔥', 'fire'], ['🌈', 'rainbow'], ['❄️', 'snowflake'], ['🍎', 'apple'], ['🍋', 'lemon'], ['🍇', 'grapes'],
];

async function digest(text: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`octapass-mock|${text}`)));
}

/** Six groups of four digits and eight emoji, like the core's fingerprint (but not the same function). */
export async function mockFingerprint(email: string): Promise<Fingerprint> {
  const bytes = await digest(`fingerprint|${email}`);
  const groups = Array.from({ length: 6 }, (_, i) => String(((bytes[2 * i]! << 8) | bytes[2 * i + 1]!) % 10_000).padStart(4, '0'));
  const emoji = Array.from({ length: 8 }, (_, i) => {
    const [symbol, name] = EMOJI[bytes[12 + i]! % EMOJI.length]!;
    return { emoji: symbol, name };
  });
  return { digits: groups.join(' '), emoji };
}

export async function mockAccountId(email: string): Promise<string> {
  return `acct-${bytesToHex((await digest(`id|${email}`)).slice(0, 8))}`;
}

/** Every well-formed email has a pretend account, except at `.invalid` domains. */
export function hasMockAccount(email: string): boolean {
  return !email.endsWith('.invalid');
}

export async function mockLookup(email: string): Promise<AccountLookup> {
  return {
    accountId: await mockAccountId(email),
    email,
    publicEncKey: base64UrlEncode(await digest(`enc|${email}`)),
    publicSignKey: base64UrlEncode(await digest(`sign|${email}`)),
    fingerprint: await mockFingerprint(email),
  };
}
