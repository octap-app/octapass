import { setLocale } from '@octapass/web/src/i18n/core';
import { translationProblems } from '@octapass/web/src/i18n/catalogCheck';
import { catalogs, tx } from './i18n';

afterEach(() => setLocale('en'));

describe('the extension’s catalog', () => {
  it('has every English message in Arabic, with every plural form and placeholder', () => {
    expect(translationProblems(catalogs.en, catalogs.ar, 'ar')).toEqual([]);
  });

  it('counts the days since the last backup', () => {
    expect(tx('local.reminder', { count: 1 })).toMatch(/^Last backup 1 day ago\./);
    expect(tx('local.reminder', { count: 15 })).toMatch(/^Last backup 15 days ago\./);
    setLocale('ar');
    expect(tx('local.reminder', { count: 2 })).toMatch(/^آخر نسخة احتياطية قبل يومين\./);
    expect(tx('local.reminder', { count: 15 })).toMatch(/^آخر نسخة احتياطية قبل 15 يومًا\./);
  });
});
