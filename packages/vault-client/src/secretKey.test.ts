import { formatSecretKey, generateRecoveryCode, generateSecretKey, normalizeSecretKey, parseSecretKey } from './secretKey';

describe('Secret Key', () => {
  it('formats as OP1 plus 26 characters grouped 6-6-5-5-4', () => {
    expect(generateSecretKey()).toMatch(/^OP1-[0-9A-HJKMNP-TV-Z]{6}-[0-9A-HJKMNP-TV-Z]{6}-[0-9A-HJKMNP-TV-Z]{5}-[0-9A-HJKMNP-TV-Z]{5}-[0-9A-HJKMNP-TV-Z]{4}$/);
  });

  it('round-trips the bytes, ignoring case, spaces and dashes', () => {
    const bytes = Uint8Array.from({ length: 16 }, (_, i) => i * 13);
    const key = formatSecretKey(bytes);
    expect(parseSecretKey(key)).toEqual(bytes);
    expect(parseSecretKey(` ${key.toLowerCase().replaceAll('-', ' ')} `)).toEqual(bytes);
    expect(normalizeSecretKey(key.replaceAll('-', ''))).toBe(key);
  });

  it('rejects keys of the wrong version or length', () => {
    expect(parseSecretKey('OP2-AAAAAA-AAAAAA-AAAAA-AAAAA-AAAA')).toBeUndefined();
    expect(parseSecretKey('OP1-AAAAAA')).toBeUndefined();
    expect(parseSecretKey('')).toBeUndefined();
  });
});

describe('recovery code', () => {
  it('is 52 characters in groups of four', () => {
    expect(generateRecoveryCode()).toMatch(/^([0-9A-HJKMNP-TV-Z]{4}-){12}[0-9A-HJKMNP-TV-Z]{4}$/);
  });
});
