import { direction, formatDate, formatNumber, formatRelative, getLocale, resolveLocale, setLocale, t, translator } from '.';

afterEach(() => setLocale('en'));

describe('t', () => {
  it('fills placeholders and formats numbers', () => {
    expect(t('list.searchPlaceholder', { count: 1248 })).toBe('Search 1,248 items');
  });

  it('chooses the plural form', () => {
    expect(t('trash.daysLeft', { count: 1 })).toBe('Deleted for good in 1 day');
    expect(t('trash.daysLeft', { count: 12 })).toBe('Deleted for good in 12 days');
  });

  it('uses all six Arabic plural forms', () => {
    setLocale('ar');
    const days = (count: number) => t('trash.daysLeft', { count });
    expect(days(0)).toBe('يُحذف نهائيًا اليوم');
    expect(days(1)).toBe('يُحذف نهائيًا خلال يوم واحد');
    expect(days(2)).toBe('يُحذف نهائيًا خلال يومين');
    expect(days(3)).toBe('يُحذف نهائيًا خلال 3 أيام');
    expect(days(10)).toBe('يُحذف نهائيًا خلال 10 أيام');
    expect(days(11)).toBe('يُحذف نهائيًا خلال 11 يومًا');
    expect(days(99)).toBe('يُحذف نهائيًا خلال 99 يومًا');
    expect(days(100)).toBe('يُحذف نهائيًا خلال 100 يوم');
    expect(days(103)).toBe('يُحذف نهائيًا خلال 103 أيام');
  });

  it('writes Arabic numbers with Western digits', () => {
    setLocale('ar');
    expect(t('list.searchPlaceholder', { count: 1248 })).toBe('ابحث في 1,248 عنصرًا');
    expect(formatNumber(1234567)).toBe('1,234,567');
  });

  it('keeps inserted text in its own direction in right-to-left languages', () => {
    expect(t('members.invited', { email: 'ada@example.com', vault: 'Team' })).toBe('ada@example.com can now open Team');
    setLocale('ar');
    expect(t('members.invited', { email: 'ada@example.com', vault: 'Team' })).toBe('أصبح بإمكان ⁨ada@example.com⁩ فتح ⁨Team⁩');
  });
});

describe('translator', () => {
  const tr = translator({ en: { hi: 'Hello {name}', only: 'English only' }, ar: { hi: 'مرحبًا {name}', only: '' } });

  it('follows the language that’s set', () => {
    expect(tr('hi', { name: 'Ada' })).toBe('Hello Ada');
    setLocale('ar');
    expect(tr('hi', { name: 'Ada' })).toBe('مرحبًا ⁨Ada⁩');
  });

  it('throws for a key nobody has', () => {
    expect(() => tr('nope' as 'hi')).toThrow('Missing message: nope');
  });
});

describe('resolveLocale', () => {
  it('follows the first system language we have', () => {
    expect(resolveLocale('system', ['ar-EG', 'en-US'])).toBe('ar');
    expect(resolveLocale('system', ['fr-FR', 'ar'])).toBe('ar');
    expect(resolveLocale('system', ['en-GB', 'ar'])).toBe('en');
    expect(resolveLocale('system', ['fr-FR', 'de'])).toBe('en');
    expect(resolveLocale('system', [])).toBe('en');
  });

  it('uses the language chosen in Settings over the system’s', () => {
    expect(resolveLocale('en', ['ar-SA'])).toBe('en');
    expect(resolveLocale('ar', ['en-US'])).toBe('ar');
  });
});

describe('direction', () => {
  it('is right to left for Arabic only', () => {
    expect(direction('en')).toBe('ltr');
    expect(direction('ar')).toBe('rtl');
    setLocale('ar');
    expect(getLocale()).toBe('ar');
    expect(direction()).toBe('rtl');
  });
});

describe('formatDate', () => {
  it('names the month in the language that’s set', () => {
    expect(formatDate('2026-10-24T12:00:00Z')).toBe('Oct 24, 2026');
    setLocale('ar');
    expect(formatDate('2026-10-24T12:00:00Z')).toBe('24 أكتوبر 2026');
  });
});

describe('formatRelative', () => {
  const now = Date.parse('2026-10-24T12:00:00Z');
  it('uses the largest unit that fits', () => {
    expect(formatRelative('2026-10-24T11:59:40Z', now)).toBe('this minute');
    expect(formatRelative('2026-10-24T11:55:00Z', now)).toBe('5 minutes ago');
    expect(formatRelative('2026-10-23T12:00:00Z', now)).toBe('yesterday');
    expect(formatRelative('2026-10-27T12:00:00Z', now)).toBe('in 3 days');
  });

  it('says it in Arabic too', () => {
    setLocale('ar');
    expect(formatRelative('2026-10-23T12:00:00Z', now)).toBe('أمس');
    expect(formatRelative('2026-10-27T12:00:00Z', now)).toBe('خلال 3 أيام');
  });
});
