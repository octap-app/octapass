import { dateMatches, repeatMatches, separatorMatches, sequenceMatches } from './patterns';

const spans = (matches: { i: number; j: number }[]) => matches.map((m) => [m.i, m.j]);

describe('sequenceMatches', () => {
  it('finds ascending and descending runs of letters and digits', () => {
    expect(spans(sequenceMatches('xabcdy9876'))).toEqual([
      [1, 4],
      [6, 9],
    ]);
    expect(sequenceMatches('ZYX')[0]!.log10).toBeCloseTo(Math.log10(4 * 3 * 2));
  });

  it('ignores runs shorter than three and runs that cross character classes', () => {
    expect(sequenceMatches('ab12')).toEqual([]);
    expect(sequenceMatches('9:;')).toEqual([]);
  });
});

describe('repeatMatches', () => {
  it('guesses the base once, then the repeat count', () => {
    const [match] = repeatMatches('xabcabcabc', () => 2);
    expect(match).toMatchObject({ i: 1, j: 9, kind: 'repeat' });
    expect(match!.log10).toBeCloseTo(2 + Math.log10(3));
  });

  it('prefers the longer greedy match', () => {
    expect(spans(repeatMatches('aabaab', () => 1))).toEqual([[0, 5]]);
  });
});

describe('separatorMatches', () => {
  it('marks lone common separators', () => {
    expect(spans(separatorMatches('a-b c!d'))).toEqual([
      [1, 1],
      [3, 3],
    ]);
  });
});

describe('dateMatches', () => {
  const at = (password: string) => spans(dateMatches(password, 2026));

  it('finds years from 1900 to 2099', () => {
    expect(at('x1987y')).toEqual([[1, 4]]);
    expect(at('1899')).toEqual([]);
  });

  it('finds dates with a repeated separator, year first or last', () => {
    expect(at('13/05/90')).toContainEqual([0, 7]);
    expect(at('1990-05-13')).toContainEqual([0, 9]);
    expect(at('13/05-90')).toEqual([]);
  });

  it('finds six- and eight-digit dates without separators', () => {
    expect(at('130590')).toContainEqual([0, 5]);
    expect(at('19900513')).toContainEqual([0, 7]);
    expect(at('139905')).toEqual([]);
  });

  it('charges more for years far from the reference year', () => {
    const [near] = dateMatches('2020', 2026);
    const [far] = dateMatches('1920', 2026);
    expect(near!.log10).toBeCloseTo(Math.log10(20));
    expect(far!.log10).toBeCloseTo(Math.log10(106));
  });
});
