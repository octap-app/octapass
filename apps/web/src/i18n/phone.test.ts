import { translationProblems } from './catalogCheck';
import { setLocale } from './core';
import { catalogs, tm } from './phone';

afterEach(() => setLocale('en'));

describe('the phone apps’ catalog', () => {
  it('has every English message in Arabic, with every plural form and placeholder', () => {
    expect(translationProblems(catalogs.en, catalogs.ar, 'ar')).toEqual([]);
  });

  it('counts down the QR code in both languages', () => {
    expect(tm('qrHidesIn', { count: 9 })).toBe('Hides in 9 s');
    setLocale('ar');
    expect(tm('qrHidesIn', { count: 9 })).toBe('يختفي خلال 9 ثوانٍ');
    expect(tm('qrHidesIn', { count: 1 })).toBe('يختفي خلال ثانية واحدة');
  });
});
