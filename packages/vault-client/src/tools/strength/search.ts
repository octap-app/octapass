import type { Match } from './match';

// Bit per character class; the lookup table turns a set of classes into its cardinality.
const LOWER = 1, UPPER = 2, DIGIT = 4, SYMBOL = 8, OTHER = 16;
const CARDINALITY = [26, 26, 10, 33, 100];
const CARDINALITY_BY_MASK = Array.from({ length: 32 }, (_, mask) =>
  CARDINALITY.reduce((sum, size, bit) => (mask & (1 << bit) ? sum + size : sum), 0),
);

function classBit(code: number): number {
  if (code >= 97 && code <= 122) return LOWER;
  if (code >= 65 && code <= 90) return UPPER;
  if (code >= 48 && code <= 57) return DIGIT;
  if (code >= 32 && code <= 126) return SYMBOL;
  return OTHER;
}

// zxcvbn's floors for a match that is only part of the password, so tiny pieces are never nearly free.
const MIN_SUBMATCH_LOG10 = { single: 1, multi: Math.log10(50) };

const LOG10_FACTORIAL = [0];
function log10Factorial(n: number): number {
  for (let k = LOG10_FACTORIAL.length; k <= n; k++) LOG10_FACTORIAL[k] = LOG10_FACTORIAL[k - 1]! + Math.log10(k);
  return LOG10_FACTORIAL[n]!;
}

interface Step {
  match: Match;
  pieces: number;
  /** log10 of the product of the pieces' guesses. */
  product: number;
  /** log10 of pieces! × product: the factorial counts the orders an attacker would try the pieces in. */
  total: number;
  previous: Step | undefined;
}

/**
 * The cheapest way to cover the password with matches and brute-force gaps (zxcvbn's search).
 * `best[k]` holds the covers of password[0..k] worth keeping, by ascending piece count: a cover with
 * more pieces is kept only while it is cheaper than every cover with fewer.
 */
export function mostGuessable(password: string, matches: Match[]): { log10: number; sequence: Match[] } {
  const n = password.length;
  if (n === 0) return { log10: 0, sequence: [] };
  const bits = Array.from({ length: n }, (_, k) => classBit(password.charCodeAt(k)));
  const byEnd: Match[][] = Array.from({ length: n }, () => []);
  for (const m of matches) byEnd[m.j]!.push(m);
  const best: Step[][] = Array.from({ length: n }, () => []);

  const floored = (i: number, j: number, log10: number) => {
    if (i === 0 && j === n - 1) return log10;
    return Math.max(log10, i === j ? MIN_SUBMATCH_LOG10.single : MIN_SUBMATCH_LOG10.multi);
  };

  const update = (i: number, j: number, log10: number, previous: Step | undefined, match: () => Match) => {
    const pieces = (previous?.pieces ?? 0) + 1;
    const product = floored(i, j, log10) + (previous?.product ?? 0);
    const total = log10Factorial(pieces) + product;
    const steps = best[j]!;
    let at = 0;
    while (at < steps.length && steps[at]!.pieces <= pieces) at++;
    if (at > 0 && steps[at - 1]!.total <= total) return;
    let end = at;
    while (end < steps.length && steps[end]!.total >= total) end++;
    const replaces = at > 0 && steps[at - 1]!.pieces === pieces ? 1 : 0;
    steps.splice(at - replaces, end - at + replaces, { match: match(), pieces, product, total, previous });
  };

  for (let k = 0; k < n; k++) {
    for (const m of byEnd[k]!) {
      if (m.i === 0) update(m.i, k, m.log10, undefined, () => m);
      else for (const step of best[m.i - 1]!) update(m.i, k, m.log10, step, () => m);
    }
    // Brute force over [i, k] costs cardinality^length, the cardinality covering the classes it uses.
    let mask = 0;
    for (let i = k; i >= 0; i--) {
      mask |= bits[i]!;
      const log10 = (k - i + 1) * Math.log10(CARDINALITY_BY_MASK[mask]!);
      const match = (): Match => ({ i, j: k, kind: 'bruteforce', log10 });
      if (i === 0) update(i, k, log10, undefined, match);
      else {
        for (const step of best[i - 1]!) {
          // Two brute-force runs side by side are never cheaper than one, so skip that combination.
          if (step.match.kind !== 'bruteforce') update(i, k, log10, step, match);
        }
      }
    }
  }

  // Totals fall as piece counts rise, so the last cover is the cheapest.
  const last = best[n - 1]!.at(-1)!;
  const sequence: Match[] = [];
  for (let step: Step | undefined = last; step; step = step.previous) sequence.unshift(step.match);
  return { log10: last.total, sequence };
}
