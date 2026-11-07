import { COMMON_PASSWORDS } from '../../data/common-passwords';
import { EFF_LARGE_WORDLIST } from '../../data/eff-large-wordlist';
import { lowerUnits, nCk, type Match } from './match';

interface Entry {
  rank: number;
  source: NonNullable<Match['source']>;
}

export interface Dictionary {
  lookup(word: string): Entry | undefined;
  maxLength: number;
}

const MIN_WORD_LENGTH = 3;
const MAX_INPUT_LENGTH = 100;

let shared: Map<string, Entry> | undefined;

function sharedWords(): Map<string, Entry> {
  if (shared) return shared;
  shared = new Map();
  // The EFF list is unranked: an attacker who knows it needs on average its full size per word.
  for (const word of EFF_LARGE_WORDLIST) shared.set(word, { rank: EFF_LARGE_WORDLIST.length, source: 'words' });
  COMMON_PASSWORDS.forEach((word, index) => shared!.set(word, { rank: index + 1, source: 'common' }));
  return shared;
}

export function buildDictionary(userInputs: string[]): Dictionary {
  const words = sharedWords();
  const user = new Map<string, Entry>();
  const add = (word: string) => {
    if (word.length >= MIN_WORD_LENGTH && !user.has(word)) user.set(word, { rank: user.size + 1, source: 'user' });
  };
  for (const input of userInputs) {
    const lower = lowerUnits(input.trim().slice(0, MAX_INPUT_LENGTH));
    const tokens = lower.split(/[^\p{L}\p{N}]+/u);
    add(lower);
    // A full name or email is also typed run together, and guessed piece by piece.
    add(tokens.join(''));
    for (const token of tokens) add(token);
  }
  let maxLength = 11;
  for (const word of user.keys()) maxLength = Math.max(maxLength, word.length);
  return {
    maxLength,
    lookup(word) {
      const a = user.get(word);
      const b = words.get(word);
      return a && b ? (a.rank <= b.rank ? a : b) : (a ?? b);
    },
  };
}

const LEET: Record<string, string> = { '4': 'a', '@': 'a', '3': 'e', '0': 'o', '5': 's', $: 's', '7': 't' };

function unleet(lower: string, one: 'i' | 'l'): string {
  let out = '';
  for (const unit of lower.split('')) out += unit === '1' ? one : (LEET[unit] ?? unit);
  return out;
}

function uppercaseVariations(token: string): number {
  if (!/[A-Z]/.test(token)) return 1;
  if (/^[A-Z][^A-Z]+$/.test(token) || /^[^A-Z]+[A-Z]$/.test(token) || !/[a-z]/.test(token)) return 2;
  const upper = token.replace(/[^A-Z]/g, '').length;
  const lower = token.replace(/[^a-z]/g, '').length;
  let variations = 0;
  for (let k = 1; k <= Math.min(upper, lower); k++) variations += nCk(upper + lower, k);
  return variations;
}

function leetVariations(token: string, word: string): number {
  const subs = new Map<string, string>();
  for (let k = 0; k < token.length; k++) if (token[k] !== word[k]) subs.set(token[k]!, word[k]!);
  let variations = 1;
  for (const [subbed, letter] of subs) {
    const s = token.split(subbed).length - 1;
    const u = token.split(letter).length - 1;
    if (u === 0) {
      variations *= 2;
    } else {
      let possibilities = 0;
      for (let k = 1; k <= Math.min(s, u); k++) possibilities += nCk(s + u, k);
      variations *= possibilities;
    }
  }
  return variations;
}

export function dictionaryMatches(password: string, dictionary: Dictionary): Match[] {
  const lower = lowerUnits(password);
  const leetForms = [unleet(lower, 'i'), unleet(lower, 'l')];
  const reversed = lower.split('').reverse().join('');
  const n = password.length;
  const matches: Match[] = [];
  for (let i = 0; i < n; i++) {
    const end = Math.min(n, i + dictionary.maxLength);
    for (let j = i + MIN_WORD_LENGTH - 1; j < end; j++) {
      const token = lower.slice(i, j + 1);
      let best: Omit<Match, 'i' | 'j' | 'kind'> | undefined;
      const consider = (word: string, extraLog10: () => number) => {
        const entry = dictionary.lookup(word);
        if (!entry) return;
        const log10 = Math.log10(entry.rank) + extraLog10();
        if (!best || log10 < best.log10) best = { log10, source: entry.source };
      };
      consider(token, () => 0);
      for (const form of leetForms) {
        const word = form.slice(i, j + 1);
        if (word !== token) consider(word, () => Math.log10(leetVariations(token, word)));
      }
      consider(reversed.slice(n - 1 - j, n - i), () => Math.log10(2));
      if (best) {
        const caps = Math.log10(uppercaseVariations(password.slice(i, j + 1)));
        matches.push({ i, j, kind: 'dictionary', log10: best.log10 + caps, source: best.source });
      }
    }
  }
  return matches;
}
