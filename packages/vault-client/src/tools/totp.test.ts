import { hotpCounter, isHotp, isValidTotp, nextHotp, parseTotp, totpCode, withHotpCounter } from './totp';

// RFC 6238 Appendix B seeds, base32: "1234567890" repeated to 20, 32 and 64 bytes.
const SHA1_SEED = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
const SHA256_SEED = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA';
const SHA512_SEED =
  'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA';

const uri = (seed: string, algorithm: string) => `otpauth://totp/RFC:test?secret=${seed}&algorithm=${algorithm}&digits=8`;

describe('totpCode', () => {
  it.each([
    [59, '94287082', '46119246', '90693936'],
    [1111111109, '07081804', '68084774', '25091201'],
    [1111111111, '14050471', '67062674', '99943326'],
    [1234567890, '89005924', '91819424', '93441116'],
    [2000000000, '69279037', '90698825', '38618901'],
    [20000000000, '65353130', '77737706', '47863826'],
  ])('matches the RFC 6238 vectors at T=%i', async (seconds, sha1, sha256, sha512) => {
    const at = seconds * 1000;
    expect((await totpCode(uri(SHA1_SEED, 'SHA1'), at)).code).toBe(sha1);
    expect((await totpCode(uri(SHA256_SEED, 'SHA256'), at)).code).toBe(sha256);
    expect((await totpCode(uri(SHA512_SEED, 'sha512'), at)).code).toBe(sha512);
  });

  it('defaults to six digits and reports the seconds left in the period', async () => {
    expect(await totpCode(SHA1_SEED, 59_000)).toEqual({ code: '287082', period: 30, remaining: 1 });
    expect((await totpCode(SHA1_SEED, 60_000)).remaining).toBe(30);
    expect((await totpCode(`${uri(SHA1_SEED, 'SHA1')}&period=60`, 61_500)).remaining).toBe(59);
  });

  it('rejects an invalid secret', async () => {
    await expect(totpCode('not a secret!')).rejects.toThrow('Invalid one-time code secret');
  });
});

describe('parseTotp', () => {
  it('reads an otpauth URI', () => {
    const params = parseTotp(
      'otpauth://totp/Example%20Co:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA256&digits=8&period=60',
    );
    expect(params).toMatchObject({ algorithm: 'SHA-256', digits: 8, period: 60, issuer: 'Example', account: 'alice@example.com' });
    expect(params.secret).toHaveLength(10);
  });

  it('takes the issuer from the label when the parameter is missing, and applies defaults', () => {
    expect(parseTotp('otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP')).toMatchObject({
      algorithm: 'SHA-1',
      digits: 6,
      period: 30,
      issuer: 'GitHub',
      account: 'octocat',
    });
    const bare = parseTotp('otpauth://totp/octocat?secret=JBSWY3DPEHPK3PXP');
    expect(bare.issuer).toBeUndefined();
    expect(bare.account).toBe('octocat');
  });

  it('accepts a bare secret with spaces and lowercase letters', () => {
    expect(parseTotp(' jbsw y3dp ehpk 3pxp ')).toMatchObject({ algorithm: 'SHA-1', digits: 6, period: 30 });
  });

  it.each([
    '',
    'JBSWY3DP',
    'JBSWY3DPEHPK3PX1',
    'otpauth://totp/Example:alice',
    'otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&algorithm=MD5',
    'otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&digits=5',
    'otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&digits=9',
    'otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&period=0',
    'https://example.com/?secret=JBSWY3DPEHPK3PXP',
  ])('rejects %j', (input) => {
    expect(() => parseTotp(input)).toThrow('Invalid one-time code secret');
    expect(isValidTotp(input)).toBe(false);
  });

  it('accepts valid input in isValidTotp', () => {
    expect(isValidTotp('JBSWY3DPEHPK3PXP')).toBe(true);
  });
});

describe('counter-based codes', () => {
  const hotp = (counter: number) => `otpauth://hotp/ACME:maya?secret=${SHA1_SEED}&counter=${counter}&issuer=ACME`;

  it('follows the RFC 4226 vectors and moves the counter', async () => {
    let totp = hotp(0);
    for (const [counter, code] of ['755224', '287082', '359152', '969429'].entries()) {
      const next = await nextHotp(totp);
      expect(next.code).toEqual({ code, counter });
      totp = next.totp;
    }
    expect(hotpCounter(totp)).toBe(4);
    expect(totp).toContain('issuer=ACME');
  });

  it('is a valid setup, but has no time-based code', async () => {
    expect(isValidTotp(hotp(1))).toBe(true);
    expect(isHotp(hotp(1))).toBe(true);
    expect(isHotp(SHA1_SEED)).toBe(false);
    expect(isHotp(undefined)).toBe(false);
    await expect(totpCode(hotp(1))).rejects.toThrow();
  });

  it('sets the counter, adding it when the link had none', () => {
    expect(hotpCounter(withHotpCounter(hotp(1), 9))).toBe(9);
    expect(hotpCounter(withHotpCounter(`otpauth://hotp/x?secret=${SHA1_SEED}`, 3))).toBe(3);
    expect(() => withHotpCounter(SHA1_SEED, 1)).toThrow();
    expect(() => withHotpCounter(hotp(1), -1)).toThrow();
  });
});
