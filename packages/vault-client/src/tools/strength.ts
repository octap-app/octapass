import type { StrengthEstimate, StrengthFeedback } from '../types';
import { buildDictionary, dictionaryMatches, type Dictionary } from './strength/dictionary';
import { keyboardMatches } from './strength/keyboard';
import type { Match, MatchKind } from './strength/match';
import { dateMatches, repeatMatches, separatorMatches, sequenceMatches } from './strength/patterns';
import { mostGuessable } from './strength/search';

// Longer input only adds guesses, and the search slows faster than linearly with length.
const MAX_ANALYSED_LENGTH = 100;
const MIN_LENGTH = 8;

function analyse(password: string, dictionary: Dictionary, referenceYear: number): { log10: number; sequence: Match[] } {
  const matches = [
    ...dictionaryMatches(password, dictionary),
    ...sequenceMatches(password),
    ...repeatMatches(password, (base) => analyse(base, dictionary, referenceYear).log10),
    ...keyboardMatches(password),
    ...dateMatches(password, referenceYear),
    ...separatorMatches(password),
  ];
  return mostGuessable(password, matches);
}

function scoreOf(log10: number, length: number): StrengthEstimate['score'] {
  const score = log10 < 3 ? 0 : log10 < 6 ? 1 : log10 < 8 ? 2 : log10 < 10 ? 3 : 4;
  // Cardinality-based brute force overrates short random strings: every 7-character password
  // falls to an offline attack in hours, so short ones never rate above fair.
  return length < MIN_LENGTH ? (Math.min(score, 2) as StrengthEstimate['score']) : score;
}

const FEEDBACK_BY_KIND: Record<Exclude<MatchKind, 'bruteforce' | 'separator'>, StrengthFeedback> = {
  dictionary: 'dictionaryWord',
  sequence: 'sequence',
  repeat: 'repeat',
  keyboard: 'keyboardPattern',
  date: 'date',
};

function feedbackOf(password: string, sequence: Match[]): StrengthFeedback {
  const [only] = sequence;
  if (sequence.length === 1 && only?.kind === 'dictionary' && only.source === 'common') return 'commonPassword';
  if (password.length < MIN_LENGTH) return 'tooShort';
  const size = (m: Match) => m.j - m.i + 1;
  const words = sequence.filter((m) => m.source === 'words');
  if (words.length >= 2 && words.reduce((sum, m) => sum + size(m), 0) >= 0.6 * password.length) return 'addMoreWords';
  const longest = sequence.reduce<Match | undefined>(
    (a, m) => (m.kind in FEEDBACK_BY_KIND && (!a || size(m) > size(a)) ? m : a),
    undefined,
  );
  // A pattern that explains only a sliver of the password isn't what makes it weak.
  if (!longest || size(longest) * 3 < password.length) return 'addVariety';
  return FEEDBACK_BY_KIND[longest.kind as keyof typeof FEEDBACK_BY_KIND];
}

/** A zxcvbn-style estimate of how many guesses an attacker needs. Runs locally; nothing leaves the device. */
export function estimateStrength(password: string, userInputs: string[] = []): StrengthEstimate {
  if (password.length === 0) return { score: 0, guessesLog10: 0, feedback: 'tooShort' };
  const analysed = password.slice(0, MAX_ANALYSED_LENGTH);
  const { log10, sequence } = analyse(analysed, buildDictionary(userInputs), new Date().getFullYear());
  const score = scoreOf(log10, password.length);
  return score === 4 ? { score, guessesLog10: log10 } : { score, guessesLog10: log10, feedback: feedbackOf(analysed, sequence) };
}
