import { base32Decode, base32Encode, base64UrlDecode, base64UrlEncode, bytesToHex, crockfordDecode, crockfordEncode } from './encoding';

// Not TextEncoder: under jsdom it returns a Uint8Array from another realm, which toEqual rejects.
const ascii = (text: string) => Uint8Array.from(text, (c) => c.charCodeAt(0));

describe('crockford base32', () => {
  it('encodes big-endian without padding', () => {
    expect(crockfordEncode(new Uint8Array([]))).toBe('');
    expect(crockfordEncode(new Uint8Array([0]))).toBe('00');
    expect(crockfordEncode(new Uint8Array([0xff]))).toBe('ZW');
    expect(crockfordEncode(ascii('foobar'))).toBe('CSQPYRK1E8');
  });

  it('round-trips random bytes', () => {
    for (let n = 0; n < 40; n++) {
      const bytes = crypto.getRandomValues(new Uint8Array(n));
      expect(crockfordDecode(crockfordEncode(bytes))).toEqual(bytes);
    }
  });

  it('ignores case, spaces and dashes and maps look-alikes', () => {
    expect(crockfordDecode('csqp-yrk1 e8')).toEqual(ascii('foobar'));
    expect(crockfordDecode('CSQPYRKIE8')).toEqual(ascii('foobar'));
    expect(crockfordDecode('CSQPYRKLE8')).toEqual(ascii('foobar'));
    expect(crockfordDecode('oo')).toEqual(new Uint8Array([0]));
  });

  it('rejects characters outside the alphabet', () => {
    expect(() => crockfordDecode('ABCU')).toThrow();
    expect(() => crockfordDecode('AB*C')).toThrow();
  });
});

describe('base32Decode (RFC 4648)', () => {
  it.each([
    ['', ''],
    ['MY======', 'f'],
    ['MZXQ====', 'fo'],
    ['MZXW6===', 'foo'],
    ['MZXW6YQ=', 'foob'],
    ['MZXW6YTB', 'fooba'],
    ['MZXW6YTBOI======', 'foobar'],
  ])('decodes the RFC test vector %j', (encoded, plain) => {
    expect(base32Decode(encoded)).toEqual(ascii(plain));
  });

  it('encodes the same vectors without padding', () => {
    expect(base32Encode(ascii('foobar'))).toBe('MZXW6YTBOI');
    expect(base32Encode(ascii('f'))).toBe('MY');
  });

  it('is case-insensitive and ignores spaces', () => {
    expect(base32Decode('mzxw 6ytb oi')).toEqual(ascii('foobar'));
  });

  it('rejects characters outside the alphabet', () => {
    expect(() => base32Decode('MZXW1')).toThrow();
    expect(() => base32Decode('MZ-XW')).toThrow();
  });
});

describe('bytesToHex', () => {
  it('writes two lowercase digits per byte', () => {
    expect(bytesToHex(new Uint8Array([0, 1, 0xab, 0xff]))).toBe('0001abff');
  });
});

describe('base64url', () => {
  it('uses the URL-safe alphabet without padding and round-trips', () => {
    const bytes = new Uint8Array([0xfb, 0xff, 0xbf, 0x00, 0x01]);
    expect(base64UrlEncode(bytes)).toBe('-_-_AAE');
    expect(base64UrlDecode('-_-_AAE')).toEqual(bytes);
  });
});
