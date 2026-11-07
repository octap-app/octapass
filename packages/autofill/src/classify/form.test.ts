import { scanDocument } from '../scan';
import { html, stubLayout } from '../test/layout';
import type { FieldType, FormType } from '../types';

let restore: () => void;
beforeEach(() => (restore = stubLayout()));
afterEach(() => restore());

/** Field types by id (fillable fields only) and the form type of each field's form. */
function classify(markup: string): { types: Record<string, FieldType | 'hidden'>; forms: Record<string, FormType> } {
  html(markup);
  const types: Record<string, FieldType | 'hidden'> = {};
  const forms: Record<string, FormType> = {};
  for (const form of scanDocument().forms) {
    for (const field of form.fields) {
      if (!field.element.id) continue;
      types[field.element.id] = field.fillable ? field.type : 'hidden';
      forms[field.element.id] = form.type;
    }
  }
  return { types, forms };
}

describe('login forms', () => {
  it('uses autocomplete tokens', () => {
    const { types, forms } = classify(`<form>
      <input id="u" autocomplete="username"><input id="p" type="password" autocomplete="current-password">
      <button>Go</button></form>`);
    expect(types).toEqual({ u: 'username', p: 'current-password' });
    expect(forms.u).toBe('login');
  });

  it('treats an email input in a sign-in form as the username', () => {
    const { types, forms } = classify(`<form><label for="e">Email</label><input id="e" type="email">
      <label for="p">Password</label><input id="p" type="password"><button>Sign in</button></form>`);
    expect(types).toEqual({ e: 'username', p: 'current-password' });
    expect(forms.e).toBe('login');
  });

  it('takes the text field before the password as the account field', () => {
    const { types } = classify(`<form><input id="who" name="f1"><input id="p" type="password"><button>Log in</button></form>`);
    expect(types).toEqual({ who: 'username', p: 'current-password' });
  });

  it('groups formless fields by their button, apart from a header search box', () => {
    const { types, forms } = classify(`
      <header><input id="q" type="search" placeholder="Search"><button>Search</button></header>
      <div class="panel"><input id="u" placeholder="Username"><input id="p" type="password" placeholder="Password">
        <button type="button">Log in</button></div>`);
    expect(types).toEqual({ q: 'search', u: 'username', p: 'current-password' });
    expect(forms.u).toBe('login');
  });

  it('does not split a field from its form because of a show-password toggle', () => {
    const { forms } = classify(`
      <div><input id="u" placeholder="Email"><div><input id="p" type="password"><button aria-label="Show password">👁</button></div>
      <div role="button">Sign in</div></div>`);
    expect(forms.u).toBe('login');
    expect(forms.p).toBe('login');
  });

  it('reads Arabic labels in a right-to-left form', () => {
    const { types, forms } = classify(`<form dir="rtl">
      <label for="a">البريد الإلكتروني</label><input id="a">
      <label for="b">كلمة المرور</label><input id="b" type="password"><button>تسجيل الدخول</button></form>`);
    expect(types).toEqual({ a: 'username', b: 'current-password' });
    expect(forms.a).toBe('login');
  });

  it('classifies hidden decoys but never marks them fillable', () => {
    const { types } = classify(`<form>
      <input id="u" name="email" type="email"><input id="p" type="password">
      <input id="h1" name="password2" type="password" style="display:none">
      <input id="h2" name="email2" data-rect="0 0 1 1">
      <input id="h3" name="website" style="opacity:0">
      <input id="h4" name="user" class="sr" style="position:absolute;clip:rect(1px, 1px, 1px, 1px)">
      <input id="h5" name="username" type="hidden" value="alex">
      <button>Log in</button></form>`);
    expect(types).toMatchObject({ u: 'username', p: 'current-password' });
    for (const id of ['h1', 'h2', 'h3', 'h4', 'h5']) expect(types[id]).toBe('hidden');
  });

  it('keeps a hidden username next to a password-only step', () => {
    html(`<form><input id="h" type="hidden" name="username" value="alex"><input id="p" type="password"><button>Sign in</button></form>`);
    const [form] = scanDocument().forms;
    expect(form!.type).toBe('login');
    expect(form!.fields.find((f) => f.element.id === 'h')!.type).toBe('username');
  });
});

describe('multi-step sign-in', () => {
  it('recognises the identifier step', () => {
    const { types, forms } = classify(`<form><label for="id">Email or phone</label><input id="id" type="email">
      <input id="hp" type="password" style="display:none"><button>Next</button></form>`);
    expect(types.id).toBe('username');
    expect(forms.id).toBe('identifier');
  });

  it('does not take a newsletter box for a sign-in step', () => {
    const { forms } = classify(`<form><input id="e" type="email" placeholder="Your email"><button>Subscribe</button></form>`);
    expect(forms.e).toBe('identity');
  });
});

describe('new passwords', () => {
  it('splits new and confirm in a sign-up form', () => {
    const { types, forms } = classify(`<form><h2>Create your account</h2>
      <label for="n">Full name</label><input id="n"><label for="e">Email</label><input id="e" type="email">
      <label for="p1">Password</label><input id="p1" type="password">
      <label for="p2">Repeat password</label><input id="p2" type="password"><button>Sign up</button>
      <a href="/login">Already have an account? Log in</a></form>`);
    expect(types).toEqual({ n: 'name', e: 'email', p1: 'new-password', p2: 'confirm-password' });
    expect(forms.p1).toBe('signup');
  });

  it('turns two new-password autocompletes into new + confirm', () => {
    const { types } = classify(`<form><input id="e" type="email" autocomplete="email">
      <input id="a" type="password" autocomplete="new-password"><input id="b" type="password" autocomplete="new-password">
      <button>Register</button></form>`);
    expect(types).toMatchObject({ a: 'new-password', b: 'confirm-password' });
  });

  it('reads a single sign-up password from the button', () => {
    const { types, forms } = classify(`<form><input id="e" type="email" placeholder="Email">
      <input id="p" type="password" placeholder="Password"><button>Create account</button></form>`);
    expect(types).toEqual({ e: 'email', p: 'new-password' });
    expect(forms.p).toBe('signup');
  });

  it('assigns current, new and confirm in a change-password form', () => {
    const { types, forms } = classify(`<form><label for="a">Current password</label><input id="a" type="password">
      <label for="b">New password</label><input id="b" type="password">
      <label for="c">Confirm new password</label><input id="c" type="password"><button>Save</button></form>`);
    expect(types).toEqual({ a: 'current-password', b: 'new-password', c: 'confirm-password' });
    expect(forms.a).toBe('change-password');
  });

  it('treats a reset page with new + confirm as a password change', () => {
    const { forms } = classify(`<h1>Reset password</h1><form><input id="a" type="password" placeholder="New password">
      <input id="b" type="password" placeholder="Confirm password"><button>Reset password</button></form>`);
    expect(forms.a).toBe('change-password');
  });
});

describe('one-time codes', () => {
  it('spots a code split into boxes', () => {
    html(`<form>${Array.from({ length: 6 }, (_, i) => `<input id="d${i}" maxlength="1" inputmode="numeric">`).join('')}<button>Verify</button></form>`);
    const [form] = scanDocument().forms;
    expect(form!.type).toBe('one-time-code');
    expect(form!.fields.map((f) => [f.type, f.segment])).toEqual(Array.from({ length: 6 }, (_, i) => ['one-time-code', i]));
  });

  it('reads a labelled code field', () => {
    const { types, forms } = classify(`<form><label for="c">Verification code</label><input id="c" name="x1"><button>Continue</button></form>`);
    expect(types.c).toBe('one-time-code');
    expect(forms.c).toBe('one-time-code');
  });
});

describe('cards and addresses', () => {
  it('classifies a card form without autocomplete, with month and year selects', () => {
    const months = Array.from({ length: 12 }, (_, i) => `<option>${String(i + 1).padStart(2, '0')}</option>`).join('');
    const years = Array.from({ length: 10 }, (_, i) => `<option>${2026 + i}</option>`).join('');
    const { types, forms } = classify(`<form>
      <label for="n">Name on card</label><input id="n"><label for="num">Card number</label><input id="num">
      <select id="m"><option value="">Month</option>${months}</select><select id="y">${years}</select>
      <label for="s">Security code</label><input id="s"><button>Pay</button></form>`);
    expect(types).toEqual({ n: 'cc-name', num: 'cc-number', m: 'cc-exp-month', y: 'cc-exp-year', s: 'cc-csc' });
    expect(forms.num).toBe('card');
  });

  it('classifies an address form', () => {
    const { types, forms } = classify(`<form>
      <label for="f">First name</label><input id="f"><label for="l">Last name</label><input id="l">
      <label for="a1">Address</label><input id="a1"><label for="a2">Apartment, suite</label><input id="a2">
      <label for="c">City</label><input id="c"><label for="z">ZIP code</label><input id="z">
      <label for="co">Country</label><select id="co"><option value="US">United States</option><option value="CA">Canada</option></select>
      <button>Continue</button></form>`);
    expect(types).toEqual({
      f: 'given-name', l: 'family-name', a1: 'address-line1', a2: 'address-line2', c: 'address-level2', z: 'postal-code', co: 'country',
    });
    expect(forms.f).toBe('identity');
  });

  it('does not take a phone dial-code select for a country', () => {
    const { types } = classify(`<form><label for="d">Country</label><select id="d"><option>UK (+44)</option><option>US (+1)</option></select>
      <label for="t">Mobile number</label><input id="t" type="tel"><input id="p" type="password"><button>Log in</button></form>`);
    expect(types.d).toBe('unknown');
  });
});
