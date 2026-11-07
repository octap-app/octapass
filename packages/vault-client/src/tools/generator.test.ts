import { EFF_LARGE_WORDLIST } from '../data/eff-large-wordlist';
import {
  DEFAULT_PASSPHRASE_OPTIONS,
  DEFAULT_PASSWORD_OPTIONS,
  generatePassword,
  generatorEntropyBits,
} from './generator';

const words = new Set(EFF_LARGE_WORDLIST);

describe('generatePassword (password)', () => {
  it('uses the defaults: 20 characters from every class', () => {
    for (let i = 0; i < 50; i++) {
      const p = generatePassword(DEFAULT_PASSWORD_OPTIONS);
      expect(p).toHaveLength(20);
      expect(p).toMatch(/[A-Z]/);
      expect(p).toMatch(/[a-z]/);
      expect(p).toMatch(/[0-9]/);
      expect(p).toMatch(/[^A-Za-z0-9]/);
      expect(p).not.toMatch(/["'`\\\s]/);
    }
  });

  it('clamps the length to 8..128', () => {
    expect(generatePassword({ ...DEFAULT_PASSWORD_OPTIONS, length: 2 })).toHaveLength(8);
    expect(generatePassword({ ...DEFAULT_PASSWORD_OPTIONS, length: 500 })).toHaveLength(128);
    expect(generatePassword({ ...DEFAULT_PASSWORD_OPTIONS, length: Number.NaN })).toHaveLength(20);
  });

  it('only uses enabled classes and includes each of them even at the minimum length', () => {
    for (let i = 0; i < 50; i++) {
      const p = generatePassword({ ...DEFAULT_PASSWORD_OPTIONS, length: 8, uppercase: false, symbols: false });
      expect(p).toMatch(/^[a-z0-9]{8}$/);
      expect(p).toMatch(/[a-z]/);
      expect(p).toMatch(/[0-9]/);
    }
  });

  it('falls back to lowercase and digits when no class is enabled', () => {
    const p = generatePassword({
      ...DEFAULT_PASSWORD_OPTIONS,
      uppercase: false,
      lowercase: false,
      digits: false,
      symbols: false,
    });
    expect(p).toMatch(/^[a-z0-9]{20}$/);
  });

  it('leaves out look-alike characters when asked', () => {
    const p = generatePassword({ ...DEFAULT_PASSWORD_OPTIONS, length: 128, avoidAmbiguous: true });
    expect(p).not.toMatch(/[0O1lI]/);
  });

  it('does not repeat itself', () => {
    const seen = new Set(Array.from({ length: 100 }, () => generatePassword(DEFAULT_PASSWORD_OPTIONS)));
    expect(seen.size).toBe(100);
  });
});

describe('generatePassword (passphrase)', () => {
  it('uses the defaults: 5 lowercase EFF words joined by dashes', () => {
    // A few EFF words contain a dash themselves (t-shirt, yo-yo), so there can be more than five parts.
    expect(generatePassword(DEFAULT_PASSPHRASE_OPTIONS)).toMatch(/^[a-z]+(-[a-z]+){4,}$/);
    const parts = generatePassword({ ...DEFAULT_PASSPHRASE_OPTIONS, separator: ' ' }).split(' ');
    expect(parts).toHaveLength(5);
    expect(parts.every((w) => words.has(w))).toBe(true);
  });

  it('clamps the word count to 3..12', () => {
    const opts = { ...DEFAULT_PASSPHRASE_OPTIONS, separator: ' ' };
    expect(generatePassword({ ...opts, words: 1 }).split(' ')).toHaveLength(3);
    expect(generatePassword({ ...opts, words: 40 }).split(' ')).toHaveLength(12);
  });

  it('capitalises words and appends one digit to one word', () => {
    for (let i = 0; i < 30; i++) {
      const parts = generatePassword({ ...DEFAULT_PASSPHRASE_OPTIONS, separator: ' ', capitalize: true, includeNumber: true }).split(' ');
      expect(parts).toHaveLength(5);
      expect(parts.filter((w) => /\d$/.test(w))).toHaveLength(1);
      for (const part of parts) {
        expect(part[0]).toBe(part[0]!.toUpperCase());
        expect(words.has(part.replace(/\d$/, '').toLowerCase())).toBe(true);
      }
    }
  });
});

describe('generatorEntropyBits', () => {
  it('measures passwords by pool size and length', () => {
    expect(generatorEntropyBits({ ...DEFAULT_PASSWORD_OPTIONS, uppercase: false, symbols: false, length: 10 })).toBeCloseTo(
      10 * Math.log2(36),
    );
    expect(generatorEntropyBits(DEFAULT_PASSWORD_OPTIONS)).toBeGreaterThan(120);
  });

  it('measures passphrases by word count', () => {
    expect(generatorEntropyBits(DEFAULT_PASSPHRASE_OPTIONS)).toBeCloseTo(5 * Math.log2(7776));
    expect(generatorEntropyBits({ ...DEFAULT_PASSPHRASE_OPTIONS, includeNumber: true })).toBeCloseTo(
      5 * Math.log2(7776) + Math.log2(50),
    );
  });
});
