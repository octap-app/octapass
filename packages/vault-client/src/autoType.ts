// Auto-type sequences (desktop app). The same rules as `apps/desktop/crates/autotype/src/sequence.rs`,
// which does the typing; this only checks a sequence in the item editor.

export const DEFAULT_AUTO_TYPE_SEQUENCE = '{USERNAME}{TAB}{PASSWORD}{ENTER}';
/** Password items have no username. */
export const PASSWORD_AUTO_TYPE_SEQUENCE = '{PASSWORD}{ENTER}';
export const MAX_AUTO_TYPE_DELAY_MS = 10_000;
export const MAX_AUTO_TYPE_LENGTH = 500;

export type AutoTypeSequenceError =
  | { code: 'tooLong' }
  | { code: 'unclosed'; at: number }
  | { code: 'unknown'; name: string }
  | { code: 'badDelay'; value: string };

const PLACEHOLDERS = new Set(['USERNAME', 'USER', 'PASSWORD', 'TOTP', 'TAB', 'ENTER']);

/** Why the sequence can't be typed, or undefined when it can. An empty sequence means the default. */
export function checkAutoTypeSequence(sequence: string): AutoTypeSequenceError | undefined {
  const chars = Array.from(sequence.trim());
  if (chars.length > MAX_AUTO_TYPE_LENGTH) return { code: 'tooLong' };
  for (let i = 0; i < chars.length; i++) {
    if (chars[i] !== '{') continue;
    // `{{}` and `{}}` type a brace.
    if ((chars[i + 1] === '{' || chars[i + 1] === '}') && chars[i + 2] === '}') {
      i += 2;
      continue;
    }
    const end = chars.indexOf('}', i);
    if (end < 0) return { code: 'unclosed', at: i };
    const name = chars.slice(i + 1, end).join('').trim();
    i = end;
    if (PLACEHOLDERS.has(name.toUpperCase())) continue;
    if (name.slice(0, 5).toUpperCase() === 'DELAY') {
      const value = name.slice(5).replace(/^[ =]+/, '').trim();
      if (!/^\d+$/.test(value) || Number(value) > MAX_AUTO_TYPE_DELAY_MS) return { code: 'badDelay', value };
      continue;
    }
    return { code: 'unknown', name };
  }
  return undefined;
}
