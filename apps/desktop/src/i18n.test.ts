import { setLocale } from '@octapass/web/src/i18n/core';
import { translationProblems } from '@octapass/web/src/i18n/catalogCheck';
import { catalogs, td } from './i18n';

afterEach(() => setLocale('en'));

describe('the desktop app’s catalog', () => {
  it('has every English message in Arabic, with every plural form and placeholder', () => {
    expect(translationProblems(catalogs.en, catalogs.ar, 'ar')).toEqual([]);
  });

  it('says when the clipboard clears, in Arabic too', () => {
    setLocale('ar');
    expect(td('quick.copied', { what: 'كلمة المرور', title: 'Bank', count: 30 })).toBe('تم نسخ ⁨كلمة المرور⁩ لـ ⁨Bank⁩. تُمسح الحافظة خلال 30 ثانية.');
  });
});
