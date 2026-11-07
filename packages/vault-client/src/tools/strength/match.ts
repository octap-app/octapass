export type MatchKind = 'dictionary' | 'sequence' | 'repeat' | 'keyboard' | 'date' | 'separator' | 'bruteforce';

/** A run of the password at [i, j] (inclusive) that an attacker could guess in 10^log10 tries. */
export interface Match {
  i: number;
  j: number;
  kind: MatchKind;
  log10: number;
  /** Dictionary matches only: which list the word came from. */
  source?: 'common' | 'words' | 'user';
}

export function nCk(n: number, k: number): number {
  if (k < 0 || k > n) return 0;
  let result = 1;
  for (let d = 1; d <= k; d++) result = (result * (n - d + 1)) / d;
  return result;
}

/** Lowercases code unit by code unit so indices keep lining up with the original password. */
export function lowerUnits(text: string): string {
  let out = '';
  for (const unit of text.split('')) {
    const lower = unit.toLowerCase();
    out += lower.length === 1 ? lower : unit;
  }
  return out;
}
