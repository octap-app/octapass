import { buildDictionary, dictionaryMatches } from './dictionary';

const dictionary = buildDictionary(['Ada Lovelace']);
const find = (password: string, i: number, j: number) => dictionaryMatches(password, dictionary).find((m) => m.i === i && m.j === j);

describe('dictionaryMatches', () => {
  it('ranks common passwords by popularity and EFF words by list size', () => {
    expect(find('password', 0, 7)).toMatchObject({ source: 'common', log10: Math.log10(2) });
    expect(find('xabacus', 1, 6)).toMatchObject({ source: 'words', log10: Math.log10(7776) });
  });

  it('adds the guesses for capitals, l33t and reversal', () => {
    expect(find('Password', 0, 7)!.log10).toBeCloseTo(Math.log10(2 * 2));
    expect(find('p4ssword', 0, 7)!.log10).toBeCloseTo(Math.log10(2 * 2));
    expect(find('drowssap', 0, 7)!.log10).toBeCloseTo(Math.log10(2 * 2));
    expect(find('l1nk', 0, 3)).toBeUndefined();
  });

  it('includes the user inputs and their parts', () => {
    expect(find('ada lovelace', 0, 11)).toMatchObject({ source: 'user', log10: 0 });
    expect(find('adalovelace', 0, 10)).toMatchObject({ source: 'user', log10: Math.log10(2) });
    expect(find('xlovelace', 1, 8)).toMatchObject({ source: 'user' });
  });
});
