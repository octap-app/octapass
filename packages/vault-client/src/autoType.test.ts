import { describe, expect, it } from 'vitest';
import { checkAutoTypeSequence, DEFAULT_AUTO_TYPE_SEQUENCE } from './autoType';

describe('checkAutoTypeSequence', () => {
  it('accepts the placeholders in any case, delays, text and braces', () => {
    for (const sequence of [
      DEFAULT_AUTO_TYPE_SEQUENCE,
      '',
      'hi {username}{Tab}x{DELAY 250}{password}{enter}é',
      '{DELAY=10}{TOTP}{user}',
      '{{}a{}}{TAB}{}}',
      '}',
      '{ PASSWORD }',
    ]) {
      expect(checkAutoTypeSequence(sequence), sequence).toBeUndefined();
    }
  });

  it('explains mistakes as the desktop app would', () => {
    expect(checkAutoTypeSequence('ab{TAB')).toEqual({ code: 'unclosed', at: 2 });
    expect(checkAutoTypeSequence('{PASSWROD}')).toEqual({ code: 'unknown', name: 'PASSWROD' });
    for (const value of ['', 'abc', '-5', '10001', '1.5']) {
      expect(checkAutoTypeSequence(`{DELAY ${value}}`), value).toEqual({ code: 'badDelay', value });
    }
    expect(checkAutoTypeSequence('a'.repeat(501))).toEqual({ code: 'tooLong' });
  });
});
