import { COMMON_PASSWORDS } from './common-passwords';
import { EFF_LARGE_WORDLIST } from './eff-large-wordlist';
import { registrableDomain } from '../tools/url';
import { PASSKEY_DOMAINS } from './passkey-domains';
import { TWO_FACTOR_DOMAINS } from './two-factor-domains';

describe('EFF_LARGE_WORDLIST', () => {
  it('holds the 7776 unique lowercase EFF words in dice order', () => {
    expect(EFF_LARGE_WORDLIST).toHaveLength(7776);
    expect(new Set(EFF_LARGE_WORDLIST).size).toBe(7776);
    expect(EFF_LARGE_WORDLIST[0]).toBe('abacus');
    expect(EFF_LARGE_WORDLIST.at(-1)).toBe('zoom');
    expect(EFF_LARGE_WORDLIST.every((w) => /^[a-z-]+$/.test(w))).toBe(true);
  });

  // Documents the list's strength; it doesn't choose it (the list is the maintainer's call).
  it('gives about 12.9 bits per word, so five words are about 64.6 bits', () => {
    expect(EFF_LARGE_WORDLIST.length).toBe(6 ** 5);
    const bitsPerWord = Math.log2(new Set(EFF_LARGE_WORDLIST).size);
    expect(bitsPerWord).toBeCloseTo(12.925, 3);
    expect(5 * bitsPerWord).toBeCloseTo(64.62, 2);
    expect(3 * bitsPerWord).toBeCloseTo(38.77, 2);
  });
});

describe('COMMON_PASSWORDS', () => {
  it('holds about a thousand unique lowercase passwords, most common first', () => {
    expect(COMMON_PASSWORDS.length).toBeGreaterThan(990);
    expect(new Set(COMMON_PASSWORDS).size).toBe(COMMON_PASSWORDS.length);
    expect(COMMON_PASSWORDS.slice(0, 2)).toEqual(['123456', 'password']);
    expect(COMMON_PASSWORDS.every((p) => p === p.toLowerCase() && p.length > 0)).toBe(true);
  });
});

describe('TWO_FACTOR_DOMAINS', () => {
  it('holds registrable domains only', () => {
    expect(TWO_FACTOR_DOMAINS.size).toBeGreaterThanOrEqual(60);
    for (const domain of TWO_FACTOR_DOMAINS) expect(domain).toMatch(/^[a-z0-9-]+\.[a-z]+$/);
    expect(TWO_FACTOR_DOMAINS.has('github.com')).toBe(true);
    expect(TWO_FACTOR_DOMAINS.has('netflix.com')).toBe(false);
  });
});

describe('PASSKEY_DOMAINS', () => {
  it('holds registrable domains, sorted and unique, from the directory snapshot', () => {
    const domains = [...PASSKEY_DOMAINS];
    expect(domains.length).toBeGreaterThanOrEqual(300);
    expect(domains).toEqual([...domains].sort());
    for (const domain of domains) {
      expect(domain).toMatch(/^[a-z0-9-]+(\.[a-z0-9-]+)+$/);
      expect(registrableDomain(domain)).toBe(domain);
    }
    expect(PASSKEY_DOMAINS.has('github.com')).toBe(true);
    expect(PASSKEY_DOMAINS.has('example.com')).toBe(false);
  });
});
