import { uuidv7, uuidv7Time } from './ids';

describe('uuidv7', () => {
  it('has the version 7 layout and encodes the timestamp', () => {
    const id = uuidv7(0x0189_7a3c_1d2e);
    expect(id).toMatch(/^01897a3c-1d2e-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  });

  it('sorts by creation time', () => {
    expect(uuidv7(1_000) < uuidv7(2_000)).toBe(true);
  });

  it('gives its creation time back', () => {
    expect(uuidv7Time(uuidv7(1_761_200_000_123))).toBe(1_761_200_000_123);
  });
});
