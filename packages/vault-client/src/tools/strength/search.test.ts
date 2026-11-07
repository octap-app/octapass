import type { Match } from './match';
import { mostGuessable } from './search';

describe('mostGuessable', () => {
  it('brute-forces by the cardinality of the classes used', () => {
    expect(mostGuessable('abcd', []).log10).toBeCloseTo(4 * Math.log10(26));
    expect(mostGuessable('aB3$', []).log10).toBeCloseTo(4 * Math.log10(26 + 26 + 10 + 33));
  });

  it('picks the cheapest cover and charges for the number of pieces', () => {
    const word: Match = { i: 0, j: 7, kind: 'dictionary', log10: 3 };
    const { log10, sequence } = mostGuessable('abcdefgh12', [word]);
    expect(sequence.map((m) => m.kind)).toEqual(['dictionary', 'bruteforce']);
    expect(log10).toBeCloseTo(Math.log10(2) + 3 + 2);
  });

  it('floors partial matches so tiny pieces are never free', () => {
    const cheap: Match = { i: 0, j: 1, kind: 'sequence', log10: 0 };
    expect(mostGuessable('ab1', [cheap]).log10).toBeCloseTo(Math.log10(2) + Math.log10(50) + 1);
  });

  it('returns zero guesses for the empty string', () => {
    expect(mostGuessable('', [])).toEqual({ log10: 0, sequence: [] });
  });
});
