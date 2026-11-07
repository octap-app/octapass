import { fieldHints, normalize, words } from './text';

describe('normalize', () => {
  it('folds case, Latin accents and whitespace', () => {
    expect(normalize('  Contraseña  ACTUELLE ')).toBe('contrasena actuelle');
    expect(normalize('Prénom')).toBe('prenom');
  });

  it('unifies Arabic letter variants and drops diacritics', () => {
    expect(normalize('كلمة المرور')).toBe(normalize('كلمه المرور'));
    expect(normalize('أدخل')).toBe('ادخل');
    expect(normalize('كَلِمة')).toBe('كلمه');
  });

  it('keeps Devanagari vowel signs', () => {
    expect(normalize('पासवर्ड')).toBe('पासवर्ड');
  });

  it('narrows full-width characters', () => {
    expect(normalize('ＰＡＳＳ')).toBe('pass');
  });
});

describe('words', () => {
  it('splits identifiers', () => {
    expect(words('userName')).toBe('user name');
    expect(words('login_email-field')).toBe('login email field');
  });
});

describe('fieldHints', () => {
  it('collects labels, aria, placeholder and attributes', () => {
    document.body.innerHTML = `
      <span id="l1">Work</span><span id="l2">email</span>
      <label for="f">Your login</label>
      <input id="f" name="loginEmail" placeholder="name@example.com" aria-labelledby="l1 l2" autocomplete="section-a username" title="Hint">`;
    const hints = fieldHints(document.querySelector('input')!);
    expect(hints.label).toEqual(['your login', 'work', 'email']);
    expect(hints.attribute).toEqual(['login email', 'f']);
    expect(hints.placeholder).toEqual(['name@example.com']);
    expect(hints.autocomplete).toEqual(['section-a', 'username']);
    expect(hints.description).toEqual(['hint']);
  });

  it('reads a wrapping label without the options of the select inside it', () => {
    document.body.innerHTML = `<label>Country <select><option>Spain</option></select></label>`;
    expect(fieldHints(document.querySelector('select')!).label).toEqual(['country']);
  });

  it('falls back to short text right before the field', () => {
    document.body.innerHTML = `<div><span>Password</span><input type="password"></div>`;
    expect(fieldHints(document.querySelector('input')!).label).toEqual(['password']);
  });

  it('ignores long help text before the field', () => {
    document.body.innerHTML = `<div><p>We will never share this with anyone, and you can change it at any time later.</p><input></div>`;
    expect(fieldHints(document.querySelector('input')!).label).toEqual([]);
  });
});
