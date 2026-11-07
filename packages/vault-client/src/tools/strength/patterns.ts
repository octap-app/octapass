import type { Match } from './match';

type CharClass = 'lower' | 'upper' | 'digit' | 'other';

function classOf(code: number): CharClass {
  if (code >= 97 && code <= 122) return 'lower';
  if (code >= 65 && code <= 90) return 'upper';
  if (code >= 48 && code <= 57) return 'digit';
  return 'other';
}

/** abc, 6789, ZYX: runs that step by one through letters or digits. */
export function sequenceMatches(password: string): Match[] {
  const matches: Match[] = [];
  const code = (k: number) => password.charCodeAt(k);
  const linked = (k: number, delta: number) =>
    code(k + 1) - code(k) === delta && classOf(code(k)) === classOf(code(k + 1)) && classOf(code(k)) !== 'other';
  let i = 0;
  while (i < password.length - 1) {
    const delta = code(i + 1) - code(i);
    if (Math.abs(delta) !== 1 || !linked(i, delta)) {
      i++;
      continue;
    }
    let j = i + 1;
    while (j + 1 < password.length && linked(j, delta)) j++;
    const length = j - i + 1;
    if (length >= 3) {
      const first = password[i]!;
      const base = 'aAzZ019'.includes(first) ? 4 : classOf(code(i)) === 'digit' ? 10 : 26;
      matches.push({ i, j, kind: 'sequence', log10: Math.log10(base * length * (delta > 0 ? 1 : 2)) });
    }
    i = j;
  }
  return matches;
}

/** aaa, abcabc: the repeated unit is guessed once (via `guessBase`), then the repeat count. */
export function repeatMatches(password: string, guessBase: (base: string) => number): Match[] {
  const greedy = /(.+)\1+/gsu;
  const lazy = /(.+?)\1+/gsu;
  const lazyAnchored = /^(.+?)\1+$/su;
  const matches: Match[] = [];
  let last = 0;
  while (last < password.length) {
    greedy.lastIndex = lazy.lastIndex = last;
    const g = greedy.exec(password);
    const l = lazy.exec(password);
    if (!g || !l) break;
    const useGreedy = g[0].length > l[0].length;
    const match = useGreedy ? g : l;
    const base = useGreedy ? lazyAnchored.exec(g[0])![1]! : l[1]!;
    const i = match.index;
    const j = i + match[0].length - 1;
    matches.push({ i, j, kind: 'repeat', log10: guessBase(base) + Math.log10(match[0].length / base.length) });
    last = j + 1;
  }
  return matches;
}

const SEPARATORS = ' -_.,';

/**
 * A lone space, dash, underscore, dot or comma between words is one of a handful of choices, not one of
 * 33 symbols. The search's single-character floor (10 guesses) then applies.
 */
export function separatorMatches(password: string): Match[] {
  const matches: Match[] = [];
  for (let i = 0; i < password.length; i++) {
    if (SEPARATORS.includes(password[i]!)) matches.push({ i, j: i, kind: 'separator', log10: Math.log10(SEPARATORS.length) });
  }
  return matches;
}

const MIN_YEAR_SPACE = 20;

function yearSpace(year: number, referenceYear: number): number {
  return Math.max(Math.abs(year - referenceYear), MIN_YEAR_SPACE);
}

function fullYear(digits: string): number | undefined {
  const value = Number(digits);
  if (digits.length === 2) return value > 50 ? 1900 + value : 2000 + value;
  if (digits.length === 4 && value >= 1900 && value <= 2099) return value;
  return undefined;
}

const validDay = (d: string) => d.length <= 2 && Number(d) >= 1 && Number(d) <= 31;
const validMonth = (m: string) => m.length <= 2 && Number(m) >= 1 && Number(m) <= 12;

/** The year if (a, b, c) reads as a date with the year first or last, in either day/month order. */
function dateYear(a: string, b: string, c: string): number | undefined {
  const dayMonth = (x: string, y: string) => (validDay(x) && validMonth(y)) || (validMonth(x) && validDay(y));
  const last = fullYear(c);
  if (last !== undefined && dayMonth(a, b)) return last;
  const first = fullYear(a);
  if (first !== undefined && dayMonth(b, c)) return first;
  return undefined;
}

/** Years 1900–2099 and day/month/year dates with or without separators (13/05/1990, 1990-05-13, 130590). */
export function dateMatches(password: string, referenceYear: number): Match[] {
  const matches: Match[] = [];
  const push = (i: number, j: number, year: number, perYear: number) =>
    matches.push({ i, j, kind: 'date', log10: Math.log10(yearSpace(year, referenceYear) * perYear) });

  for (let i = 0; i + 4 <= password.length; i++) {
    const four = password.slice(i, i + 4);
    if (/^(19|20)\d\d$/.test(four)) push(i, i + 3, Number(four), 1);
  }

  const separated = /^(\d{1,4})([\s/\\_.-])(\d{1,2})\2(\d{1,4})$/;
  for (let i = 0; i < password.length; i++) {
    for (let length = 4; length <= 10 && i + length <= password.length; length++) {
      const token = password.slice(i, i + length);
      const parts = separated.exec(token);
      if (parts) {
        const year = dateYear(parts[1]!, parts[3]!, parts[4]!);
        // The separator multiplies the space: the attacker must also guess which one was used.
        if (year !== undefined) push(i, i + length - 1, year, 365 * 4);
      } else if (/^\d+$/.test(token)) {
        const year = compactDateYear(token);
        if (year !== undefined) push(i, i + length - 1, year, 365);
      }
    }
  }
  return matches;
}

/**
 * ddmmyy, mmddyy, yymmdd and their four-digit-year forms. Shorter forms (d/m/yy in 4 digits) are left
 * out: nearly every random run of digits would read as one.
 */
function compactDateYear(digits: string): number | undefined {
  if (digits.length !== 6 && digits.length !== 8) return undefined;
  const yearFirst = digits.length - 4;
  return (
    dateYear(digits.slice(0, 2), digits.slice(2, 4), digits.slice(4)) ??
    dateYear(digits.slice(0, yearFirst), digits.slice(yearFirst, yearFirst + 2), digits.slice(yearFirst + 2))
  );
}
