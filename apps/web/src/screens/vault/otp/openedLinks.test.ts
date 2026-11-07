import { describe, expect, it } from 'vitest';
import { readLink } from './openedLinks';

describe('readLink', () => {
  it('reads the issuer and account of a one-time code link', () => {
    const link = 'otpauth://totp/Example:alice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example%20Inc';
    expect(readLink(link)).toEqual({ kind: 'code', link, issuer: 'Example Inc', account: 'alice@example.com' });
  });

  it('falls back to the label’s issuer, and to none', () => {
    expect(readLink('otpauth://totp/GitHub:bob?secret=AAAA')).toMatchObject({ issuer: 'GitHub', account: 'bob' });
    expect(readLink('otpauth://hotp/bob?secret=AAAA&counter=1')).toMatchObject({ issuer: undefined, account: 'bob' });
  });

  it('takes Google Authenticator exports', () => {
    const link = 'otpauth-migration://offline?data=CjEKCkhlbGxvId6tvu8SGAoKSGVsbG8h3q2%2B7xgB';
    expect(readLink(link)).toEqual({ kind: 'export', link });
  });

  it('turns down anything else', () => {
    for (const link of ['otpauth://totp/x', 'otpauth://steam/x?secret=A', 'otpauth-migration://offline', 'https://example.com/?secret=A', 'not a link']) {
      expect(readLink(link), link).toBeUndefined();
    }
  });
});
