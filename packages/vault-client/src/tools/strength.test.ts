import { EFF_LARGE_WORDLIST } from '../data/eff-large-wordlist';
import { DEFAULT_PASSPHRASE_OPTIONS, DEFAULT_PASSWORD_OPTIONS, generatePassword } from './generator';
import { estimateStrength } from './strength';

describe('estimateStrength', () => {
  it('rates the empty string as too short', () => {
    expect(estimateStrength('')).toEqual({ score: 0, guessesLog10: 0, feedback: 'tooShort' });
  });

  it.each([
    ['password', 0],
    ['P@ssw0rd', 1],
    ['qwerty123', 1],
    ['Summer2024!', 2],
    ['abcdefghijkl', 0],
    ['aaaaaaaaaaaaaaaa', 0],
    ['13/05/1990', 1],
  ])('rates %j at most %i', (password, max) => {
    expect(estimateStrength(password).score).toBeLessThanOrEqual(max);
  });

  it('rates a four-word EFF passphrase at least 3', () => {
    expect(estimateStrength('correct-battery-staple-abacus').score).toBeGreaterThanOrEqual(3);
    expect(estimateStrength('acornzebracanopyvalid').score).toBeGreaterThanOrEqual(3);
  });

  it('rates generated passwords and six-word passphrases 4', () => {
    for (let i = 0; i < 20; i++) {
      expect(estimateStrength(generatePassword(DEFAULT_PASSWORD_OPTIONS)).score).toBe(4);
      expect(estimateStrength(generatePassword({ ...DEFAULT_PASSPHRASE_OPTIONS, words: 6 })).score).toBe(4);
    }
  });

  it('counts guesses in log10 and omits feedback at score 4', () => {
    const weak = estimateStrength('password');
    expect(weak.guessesLog10).toBeCloseTo(Math.log10(2));
    const strong = estimateStrength('xK7#mP2$vL9@qR4!');
    expect(strong.score).toBe(4);
    expect(strong.guessesLog10).toBeGreaterThan(20);
    expect(strong.feedback).toBeUndefined();
  });

  it('caps short random passwords at fair', () => {
    expect(estimateStrength('k#9Lq!2')).toMatchObject({ score: 2, feedback: 'tooShort' });
  });

  it('treats reversed, capitalised and l33t words as the dictionary word', () => {
    expect(estimateStrength('drowssap').score).toBe(0);
    expect(estimateStrength('PASSWORD').score).toBe(0);
    expect(EFF_LARGE_WORDLIST).toContain('activist');
    expect(estimateStrength('Act1v1st').score).toBeLessThanOrEqual(1);
  });

  it('uses the user inputs as dictionary words', () => {
    const inputs = ['John Barry', 'jbarry@example.com'];
    expect(estimateStrength('johnbarry77').score).toBe(4);
    expect(estimateStrength('johnbarry77', inputs).score).toBeLessThanOrEqual(1);
    expect(estimateStrength('yrrabnhoj', inputs).score).toBeLessThanOrEqual(1);
  });

  it.each([
    ['password', 'commonPassword'],
    ['P@ssw0rd', 'commonPassword'],
    ['xq7', 'tooShort'],
    ['abcdefghijkl', 'sequence'],
    ['kqkqkqkqkqkq', 'repeat'],
    [';lkjhgfdsazx', 'keyboardPattern'],
    ['13/05/1990', 'date'],
    ['Summer2024!', 'dictionaryWord'],
    ['acid-zebra', 'addMoreWords'],
    ['831825948', 'addVariety'],
  ] as const)('gives %j the feedback %j', (password, feedback) => {
    expect(estimateStrength(password).feedback).toBe(feedback);
  });

  it('analyses at most 100 characters', () => {
    expect(estimateStrength('a'.repeat(5000))).toEqual(estimateStrength('a'.repeat(100)));
  });

  it('is fast enough to run on every keystroke', () => {
    const inputs = [
      generatePassword({ ...DEFAULT_PASSWORD_OPTIONS, length: 64 }),
      generatePassword({ ...DEFAULT_PASSPHRASE_OPTIONS, words: 10, separator: '' }).slice(0, 64),
      'abcabc123123qwerty1990'.repeat(3).slice(0, 64),
      'a'.repeat(64),
    ];
    for (const input of inputs) estimateStrength(input);
    const runs = 20;
    const start = performance.now();
    for (let r = 0; r < runs; r++) for (const input of inputs) estimateStrength(input);
    expect((performance.now() - start) / (runs * inputs.length)).toBeLessThan(5);
  });
});
