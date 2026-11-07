import { keyboardMatches } from './keyboard';

describe('keyboardMatches', () => {
  it('finds qwerty walks, including turns and shifted keys', () => {
    expect(keyboardMatches('xqwertz')[0]).toMatchObject({ i: 1, j: 5, kind: 'keyboard' });
    expect(keyboardMatches('1qaz')[0]).toMatchObject({ i: 0, j: 3 });
    expect(keyboardMatches('QWERT')[0]).toMatchObject({ i: 0, j: 4 });
  });

  it('finds number-pad walks', () => {
    expect(keyboardMatches('7415963')).toContainEqual(expect.objectContaining({ i: 0, j: 6 }));
  });

  it('charges more for turns and mixed shifting', () => {
    const [straight] = keyboardMatches('asdfgh');
    const [turning] = keyboardMatches('asdews');
    const [mixed] = keyboardMatches('aSdFgH');
    expect(turning!.log10).toBeGreaterThan(straight!.log10);
    expect(mixed!.log10).toBeGreaterThan(straight!.log10);
  });

  it('ignores keys that are not neighbours', () => {
    expect(keyboardMatches('qzp')).toEqual([]);
  });
});
