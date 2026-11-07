import type { GeneratorOptions } from '../types';
import { EFF_LARGE_WORDLIST } from '../data/eff-large-wordlist';
import { randomInt } from './random';

type PasswordOptions = Extract<GeneratorOptions, { kind: 'password' }>;
type PassphraseOptions = Extract<GeneratorOptions, { kind: 'passphrase' }>;

export const DEFAULT_PASSWORD_OPTIONS: PasswordOptions = {
  kind: 'password',
  length: 20,
  uppercase: true,
  lowercase: true,
  digits: true,
  symbols: true,
  avoidAmbiguous: false,
};

export const DEFAULT_PASSPHRASE_OPTIONS: PassphraseOptions = {
  kind: 'passphrase',
  words: 5,
  separator: '-',
  capitalize: false,
  includeNumber: false,
};

const LENGTH = { min: 8, max: 128 };
const WORDS = { min: 3, max: 12 };

// No quotes, backslashes or spaces: sites and shells mangle them most often.
const CLASSES = {
  uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  lowercase: 'abcdefghijklmnopqrstuvwxyz',
  digits: '0123456789',
  symbols: '!#$%&*+-=?@^_~.:;',
} as const;
const AMBIGUOUS = /[0O1lI]/g;

function clamp(value: number, range: { min: number; max: number }, fallback: number): number {
  if (!Number.isFinite(value)) return fallback;
  return Math.min(range.max, Math.max(range.min, Math.round(value)));
}

function pick(chars: string): string {
  return chars[randomInt(chars.length)]!;
}

function characterSets(opts: PasswordOptions): string[] {
  const enabled = (Object.keys(CLASSES) as (keyof typeof CLASSES)[]).filter((name) => opts[name]);
  const names = enabled.length > 0 ? enabled : (['lowercase', 'digits'] as const);
  return names.map((name) => (opts.avoidAmbiguous ? CLASSES[name].replace(AMBIGUOUS, '') : CLASSES[name]));
}

function shuffle<T>(items: T[]): T[] {
  for (let i = items.length - 1; i > 0; i--) {
    const j = randomInt(i + 1);
    [items[i], items[j]] = [items[j]!, items[i]!];
  }
  return items;
}

function password(opts: PasswordOptions): string {
  const length = clamp(opts.length, LENGTH, DEFAULT_PASSWORD_OPTIONS.length);
  const sets = characterSets(opts);
  const all = sets.join('');
  const chars = sets.map(pick);
  while (chars.length < length) chars.push(pick(all));
  return shuffle(chars).join('');
}

function passphrase(opts: PassphraseOptions): string {
  const count = clamp(opts.words, WORDS, DEFAULT_PASSPHRASE_OPTIONS.words);
  const words = Array.from({ length: count }, () => {
    const word = EFF_LARGE_WORDLIST[randomInt(EFF_LARGE_WORDLIST.length)]!;
    return opts.capitalize ? word[0]!.toUpperCase() + word.slice(1) : word;
  });
  if (opts.includeNumber) {
    const at = randomInt(count);
    words[at] += String(randomInt(10));
  }
  return words.join(opts.separator);
}

export function generatePassword(opts: GeneratorOptions): string {
  return opts.kind === 'password' ? password(opts) : passphrase(opts);
}

/**
 * Entropy of the generator's output space, for display. For passwords this is length × log2(pool);
 * the one-of-each-class rule makes the true figure slightly lower, by well under one bit at length 12+.
 */
export function generatorEntropyBits(opts: GeneratorOptions): number {
  if (opts.kind === 'password') {
    const length = clamp(opts.length, LENGTH, DEFAULT_PASSWORD_OPTIONS.length);
    return length * Math.log2(characterSets(opts).join('').length);
  }
  const count = clamp(opts.words, WORDS, DEFAULT_PASSPHRASE_OPTIONS.words);
  const words = count * Math.log2(EFF_LARGE_WORDLIST.length);
  return opts.includeNumber ? words + Math.log2(10 * count) : words;
}
