import { randomBytes, randomInt } from './random';

describe('randomBytes', () => {
  it('returns the requested number of bytes', () => {
    expect(randomBytes(0)).toHaveLength(0);
    expect(randomBytes(32)).toHaveLength(32);
  });

  it('fills buffers larger than one getRandomValues call', () => {
    const bytes = randomBytes(70000);
    expect(bytes).toHaveLength(70000);
    expect(bytes.subarray(66000).some((b) => b !== 0)).toBe(true);
  });
});

describe('randomInt', () => {
  it('stays in range and covers every value', () => {
    const seen = new Set<number>();
    for (let i = 0; i < 2000; i++) {
      const n = randomInt(7);
      expect(n).toBeGreaterThanOrEqual(0);
      expect(n).toBeLessThan(7);
      seen.add(n);
    }
    expect(seen.size).toBe(7);
  });

  it('returns 0 for a range of one', () => {
    expect(randomInt(1)).toBe(0);
  });

  it('rejects invalid ranges', () => {
    expect(() => randomInt(0)).toThrow(RangeError);
    expect(() => randomInt(1.5)).toThrow(RangeError);
    expect(() => randomInt(2 ** 32 + 1)).toThrow(RangeError);
  });
});
