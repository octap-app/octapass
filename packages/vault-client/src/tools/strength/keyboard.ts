import { nCk, type Match } from './match';

interface Key {
  x: number;
  y: number;
  shifted: boolean;
}

interface Layout {
  keys: Map<string, Key>;
  adjacent(a: Key, b: Key): boolean;
  startingPositions: number;
  averageDegree: number;
}

function layout(
  rows: { unshifted: string; shifted?: string; x: number }[],
  adjacent: (a: Key, b: Key) => boolean,
): Layout {
  const keys = new Map<string, Key>();
  const positions: Key[] = [];
  rows.forEach((row, y) => {
    row.unshifted.split('').forEach((char, column) => {
      const key = { x: row.x + column, y, shifted: false };
      keys.set(char, key);
      positions.push(key);
      const shiftedChar = row.shifted?.[column];
      if (shiftedChar) keys.set(shiftedChar, { ...key, shifted: true });
    });
  });
  let degrees = 0;
  for (const a of positions) for (const b of positions) if (a !== b && adjacent(a, b)) degrees++;
  return { keys, adjacent, startingPositions: positions.length, averageDegree: degrees / positions.length };
}

// Rows are offset by their physical stagger, so a key touches the neighbours within ¾ of a key above and below.
const QWERTY = layout(
  [
    { unshifted: '`1234567890-=', shifted: '~!@#$%^&*()_+', x: 0 },
    { unshifted: 'qwertyuiop[]\\', shifted: 'QWERTYUIOP{}|', x: 1.5 },
    { unshifted: "asdfghjkl;'", shifted: 'ASDFGHJKL:"', x: 1.75 },
    { unshifted: 'zxcvbnm,./', shifted: 'ZXCVBNM<>?', x: 2.25 },
  ],
  (a, b) => (a.y === b.y ? Math.abs(a.x - b.x) === 1 : Math.abs(a.y - b.y) === 1 && Math.abs(a.x - b.x) <= 0.75),
);

const KEYPAD = layout(
  [
    { unshifted: '/*-', x: 1 },
    { unshifted: '789+', x: 0 },
    { unshifted: '456', x: 0 },
    { unshifted: '123', x: 0 },
    { unshifted: '0.', x: 0 },
  ],
  (a, b) => Math.max(Math.abs(a.x - b.x), Math.abs(a.y - b.y)) === 1,
);

/** zxcvbn's estimate: every walk of this length with at most `turns` direction changes. */
function walkGuesses(board: Layout, length: number, turns: number, shifted: number): number {
  let guesses = 0;
  for (let i = 2; i <= length; i++) {
    for (let j = 1; j <= Math.min(turns, i - 1); j++) {
      guesses += nCk(i - 1, j - 1) * board.startingPositions * board.averageDegree ** j;
    }
  }
  const unshifted = length - shifted;
  if (shifted > 0) {
    if (unshifted === 0) guesses *= 2;
    else {
      let variations = 0;
      for (let k = 1; k <= Math.min(shifted, unshifted); k++) variations += nCk(length, k);
      guesses *= variations;
    }
  }
  return guesses;
}

function walks(password: string, board: Layout): Match[] {
  const matches: Match[] = [];
  let i = 0;
  while (i < password.length - 1) {
    let j = i;
    let turns = 0;
    let direction = '';
    let shifted = board.keys.get(password[i]!)?.shifted ? 1 : 0;
    while (j + 1 < password.length) {
      const a = board.keys.get(password[j]!);
      const b = board.keys.get(password[j + 1]!);
      if (!a || !b || !board.adjacent(a, b)) break;
      const next = `${b.x - a.x},${b.y - a.y}`;
      if (next !== direction) {
        turns++;
        direction = next;
      }
      if (b.shifted) shifted++;
      j++;
    }
    if (j - i >= 2) {
      matches.push({ i, j, kind: 'keyboard', log10: Math.log10(walkGuesses(board, j - i + 1, turns, shifted)) });
      i = j;
    } else {
      i++;
    }
  }
  return matches;
}

export function keyboardMatches(password: string): Match[] {
  return [...walks(password, QWERTY), ...walks(password, KEYPAD)];
}
