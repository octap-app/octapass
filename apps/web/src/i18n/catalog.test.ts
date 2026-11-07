import { ar } from './ar';
import { translationProblems } from './catalogCheck';
import { en } from './en';

describe('the Arabic catalog', () => {
  it('has every English message, with every plural form and placeholder', () => {
    expect(translationProblems(en, ar, 'ar')).toEqual([]);
  });

  it('notices what a translation gets wrong', () => {
    const english = { a: 'Hello {name}', b: { one: '{count} item', other: '{count} items' }, c: 'Octa Pass', d: 'Lock' };
    const arabic = { a: 'مرحبًا', b: { one: 'عنصر', other: '{count} عنصر' }, c: 'Octa Pass', d: 'Lock', e: 'زائد' };
    expect(translationProblems(english, arabic, 'ar')).toEqual(['e: not in English', 'a: {name} is missing', 'b: no zero, two, few, many form', 'd: still in English']);
  });
});
