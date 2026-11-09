// The newer item types (plan 05, History 2026-11-08): bank accounts, database consoles, licence keys,
// ID document numbers and wallet addresses, on form fixtures written the way real sites write them.

import { createAutofill, type Autofill } from './engine';
import { planFill, runFill } from './fill/fill';
import { scanDocument } from './scan';
import { captureShadowRoots, html, stubLayout } from './test/layout';
import type { AutofillHost, FieldType, FillValues, FormType, Suggestion } from './types';

let restoreLayout: () => void;
beforeEach(() => (restoreLayout = stubLayout()));
afterEach(() => restoreLayout());

/** Field types by id (fillable fields only) and the form type of each field's form. */
function classify(markup: string): { types: Record<string, FieldType>; forms: Record<string, FormType> } {
  html(markup);
  const types: Record<string, FieldType> = {};
  const forms: Record<string, FormType> = {};
  for (const form of scanDocument().forms) {
    for (const field of form.fields) {
      if (!field.element.id || !field.fillable) continue;
      types[field.element.id] = field.type;
      forms[field.element.id] = form.type;
    }
  }
  return { types, forms };
}

function fill(markup: string, values: FillValues, formType: FormType) {
  html(markup);
  const form = scanDocument().forms.find((f) => f.type === formType)!;
  runFill(planFill(form, values), form.fields[0]!.element, () => false);
  return (id: string) => (document.getElementById(id) as HTMLInputElement).value;
}

// A payout form (a marketplace's "Get paid" page).
const SEPA_PAYOUT = `<form>
  <label for="holder">Account holder name</label><input id="holder" name="account_holder">
  <label for="iban">IBAN</label><input id="iban" name="iban" maxlength="34">
  <label for="bic">BIC / SWIFT</label><input id="bic" name="bic">
  <label for="bank">Bank name</label><input id="bank" name="bank_name">
  <button>Save payout method</button></form>`;

// A US direct deposit form, and a UK one with a sort code box that takes six digits.
const US_DEPOSIT = `<form>
  <label for="name">Name on account</label><input id="name">
  <label for="routing">Routing number</label><input id="routing" inputmode="numeric">
  <label for="acct">Account number</label><input id="acct" type="password" name="accountNumber">
  <button>Add bank account</button></form>`;
const UK_TRANSFER = `<form>
  <label for="payee">Payee name</label><input id="payee">
  <label for="sort">Sort code</label><input id="sort" maxlength="6">
  <label for="number">Account number</label><input id="number" maxlength="8">
  <button>Continue</button></form>`;

// Adminer's sign-in, as it writes it.
const ADMINER = `<form action="" method="post"><table>
  <tr><th>System</th><td><select name="auth[driver]" id="driver"><option value="server">MySQL</option><option value="pgsql">PostgreSQL</option></select></td></tr>
  <tr><th>Server</th><td><input name="auth[server]" id="server" value="" title="hostname[:port]"></td></tr>
  <tr><th>Username</th><td><input name="auth[username]" id="username" autocomplete="username"></td></tr>
  <tr><th>Password</th><td><input type="password" name="auth[password]" id="password" autocomplete="current-password"></td></tr>
  <tr><th>Database</th><td><input name="auth[db]" id="db"></td></tr>
  </table><p><input type="submit" value="Login"></p></form>`;

// A console with a port box of its own.
const PG_CONSOLE = `<form>
  <label for="h">Host</label><input id="h"><label for="pt">Port</label><input id="pt" type="number">
  <label for="d">Database name</label><input id="d"><label for="u">User</label><input id="u" name="user">
  <label for="pw">Password</label><input id="pw" type="password"><button>Connect</button></form>`;

describe('bank account forms', () => {
  it('classifies a SEPA payout form', () => {
    const { types, forms } = classify(SEPA_PAYOUT);
    expect(types).toEqual({ holder: 'bank-account-holder', iban: 'iban', bic: 'bic', bank: 'bank-name' });
    expect(forms.iban).toBe('bank');
  });

  it('classifies routing and sort codes, and a masked account number', () => {
    expect(classify(US_DEPOSIT).types).toEqual({ name: 'bank-account-holder', routing: 'bank-routing', acct: 'bank-account-number' });
    expect(classify(UK_TRANSFER)).toEqual({
      types: { payee: 'bank-account-holder', sort: 'bank-routing', number: 'bank-account-number' },
      forms: { payee: 'bank', sort: 'bank', number: 'bank' },
    });
  });

  it('leaves a sign-in that asks for an account number and sort code a sign-in', () => {
    const { types, forms } = classify(`<form>
      <label for="s">Sort code</label><input id="s"><label for="a">Account number</label><input id="a">
      <label for="p">Passcode</label><input id="p" type="password"><button>Log in</button></form>`);
    expect(types.a).toBe('username');
    expect(types.p).toBe('current-password');
    expect(types.s).not.toBe('bank-routing');
    expect(forms.a).toBe('login');
  });

  it('keeps an address form with an IBAN an address form, with the IBAN still a bank field', () => {
    const { types, forms } = classify(`<form>
      <label for="n">Full name</label><input id="n"><label for="st">Street address</label><input id="st">
      <label for="c">City</label><input id="c"><label for="z">Postcode</label><input id="z">
      <label for="i">IBAN</label><input id="i"><button>Pay by direct debit</button></form>`);
    expect(types.i).toBe('iban');
    expect(forms.i).toBe('identity');
  });

  it('reads a bank word alone as nothing outside a bank form', () => {
    const { types } = classify(`<form><label for="b">Bank</label><input id="b"><button>Search branches</button></form>`);
    expect(types.b).toBe('unknown');
  });

  it('fills the IBAN without spaces and fits a sort code to its box', () => {
    const sepa = fill(SEPA_PAYOUT, { iban: 'de89 3704 0044 0532 0130 00', bic: 'COBADEFFXXX', 'bank-account-holder': 'Ada Lovelace', 'bank-name': 'Commerzbank' }, 'bank');
    expect(['holder', 'iban', 'bic', 'bank'].map(sepa)).toEqual(['Ada Lovelace', 'DE89370400440532013000', 'COBADEFFXXX', 'Commerzbank']);
    const uk = fill(UK_TRANSFER, { 'bank-routing': '12-34-56', 'bank-account-number': '31926819', 'bank-account-holder': 'Ada Lovelace' }, 'bank');
    expect(['payee', 'sort', 'number'].map(uk)).toEqual(['Ada Lovelace', '123456', '31926819']);
  });
});

describe('database consoles', () => {
  it('classifies Adminer as a database sign-in, not a sign-up', () => {
    const { types, forms } = classify(ADMINER);
    expect(types).toMatchObject({ server: 'db-host', username: 'username', password: 'current-password', db: 'db-name' });
    expect(forms.password).toBe('database');
  });

  it('classifies a console with its own port field', () => {
    const { types, forms } = classify(PG_CONSOLE);
    expect(types).toEqual({ h: 'db-host', pt: 'db-port', d: 'db-name', u: 'username', pw: 'current-password' });
    expect(forms.pw).toBe('database');
  });

  it('leaves a self-hosted app’s server address and a plain sign-in alone', () => {
    const selfHosted = classify(`<form><label for="s">Server URL</label><input id="s" placeholder="https://cloud.example.com">
      <label for="e">Email</label><input id="e" type="email"><label for="p">Password</label><input id="p" type="password"><button>Sign in</button></form>`);
    expect(selfHosted.types.s).not.toBe('db-host');
    expect(selfHosted.forms.p).toBe('login');
    const signup = classify(`<form><label for="h">Host name</label><input id="h"><label for="pt">Port</label><input id="pt">
      <input id="n1" type="password" autocomplete="new-password"><input id="n2" type="password" autocomplete="new-password"><button>Create</button></form>`);
    expect(signup.types.h).not.toBe('db-host');
    expect(signup.types.pt).not.toBe('db-port');
  });

  it('fills host, port, database, user and password; host:port where there’s no port box', () => {
    const values: FillValues = { 'db-host': 'db.internal', 'db-port': '5432', 'db-name': 'app', username: 'admin', 'current-password': 'pw' };
    const adminer = fill(ADMINER, values, 'database');
    expect(['server', 'username', 'password', 'db'].map(adminer)).toEqual(['db.internal:5432', 'admin', 'pw', 'app']);
    const console = fill(PG_CONSOLE, values, 'database');
    expect(['h', 'pt', 'd', 'u', 'pw'].map(console)).toEqual(['db.internal', '5432', 'app', 'admin', 'pw']);
  });
});

describe('licence keys, ID numbers and wallet addresses', () => {
  it('classifies each in the words sites use, in several languages', () => {
    const { types } = classify(`
      <form><label for="lk">License key</label><input id="lk"><button>Activate</button></form>
      <form><label for="pk">Clave de producto</label><input id="pk"><button>Activar</button></form>
      <form><label for="pp">Passport number</label><input id="pp"><label for="ex">Expiry date</label><input id="ex"><button>Save traveller</button></form>
      <form><label for="hw">رقم جواز السفر</label><input id="hw"><button>متابعة</button></form>
      <form><label for="dl">Driver's licence number</label><input id="dl"><button>Verify</button></form>
      <form><label for="wa">BTC address</label><input id="wa"><label for="amt">Amount</label><input id="amt"><button>Withdraw</button></form>`);
    expect(types).toMatchObject({ lk: 'license-key', pk: 'license-key', pp: 'document-number', hw: 'document-number', dl: 'document-number', wa: 'wallet-address' });
  });

  it('never takes a seed phrase box for an address, or an emailed activation code for a licence', () => {
    const { types } = classify(`
      <form><label for="seed">Recovery phrase</label><textarea id="seed"></textarea><button>Import wallet</button></form>
      <form><label for="code">Activation code</label><input id="code" maxlength="6"><button>Verify</button></form>`);
    expect(types.seed).not.toBe('wallet-address');
    expect(types.code).not.toBe('license-key');
  });
});

describe('the menu and the fill', () => {
  let engine: Autofill | undefined;
  let shadow: ReturnType<typeof captureShadowRoots>;
  beforeEach(() => (shadow = captureShadowRoots()));
  afterEach(() => {
    engine?.stop();
    engine = undefined;
    shadow.restore();
  });

  const flush = () => new Promise((resolve) => setTimeout(resolve, 0));
  const field = (id: string) => document.getElementById(id) as HTMLInputElement;

  function start(suggestions: Suggestion[], values: FillValues): AutofillHost {
    const host: AutofillHost = { getSuggestions: vi.fn(async () => suggestions), resolve: vi.fn(async () => values) };
    engine = createAutofill({ host, testing: { trustAllEvents: true, pickDelayMs: 0 } });
    return host;
  }

  async function openMenu(id: string): Promise<HTMLElement[]> {
    field(id).focus();
    field(id).dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowDown', bubbles: true, composed: true }));
    await flush();
    const host = [...shadow.roots.keys()].find((e) => e.localName === 'octapass-menu' && e.isConnected) as HTMLElement | undefined;
    if (!host) return [];
    const items = [...shadow.roots.get(host)!.querySelectorAll<HTMLElement>('[role=option]')];
    items.forEach((item, i) => item.setAttribute('data-rect', `0 ${300 + i * 40} 260 36`));
    const stubbed = Document.prototype.elementsFromPoint;
    document.elementsFromPoint = function (x: number, y: number) {
      return y >= 300 && y < 400 ? [host] : stubbed.call(this, x, y);
    };
    return items;
  }

  const BANK: Suggestion = { kind: 'bank-account', id: 'b1', title: 'Savings', subtitle: '•••• 3000' };
  const DB: Suggestion = { kind: 'database', id: 'd1', title: 'Production', subtitle: 'db.internal' };
  const LOGIN: Suggestion = { kind: 'login', id: 'l1', title: 'Adminer', username: 'me' };

  it('offers bank accounts in bank fields and fills the whole form after a pick', async () => {
    html(SEPA_PAYOUT);
    const host = start([BANK, LOGIN], { iban: 'DE89370400440532013000', 'bank-account-holder': 'Ada Lovelace', bic: 'COBADEFFXXX' });
    const items = await openMenu('iban');
    expect(host.getSuggestions).toHaveBeenCalledWith(expect.objectContaining({ fieldType: 'iban', formType: 'bank' }));
    expect(items.map((i) => i.textContent)).toEqual([expect.stringContaining('Savings')]);
    items[0]!.click();
    await flush();
    expect(['holder', 'iban', 'bic'].map((id) => field(id).value)).toEqual(['Ada Lovelace', 'DE89370400440532013000', 'COBADEFFXXX']);
  });

  it('offers the site’s logins and then databases in a console’s sign-in', async () => {
    html(ADMINER);
    start([DB, LOGIN], { 'db-host': 'db.internal', username: 'admin', 'current-password': 'pw', 'db-name': 'app' });
    expect((await openMenu('username')).map((i) => i.textContent)).toEqual([expect.stringContaining('Production'), expect.stringContaining('Adminer')]);
    const inServer = await openMenu('server');
    expect(inServer).toHaveLength(1);
    inServer[0]!.click();
    await flush();
    expect(['server', 'username', 'password', 'db'].map((id) => field(id).value)).toEqual(['db.internal', 'admin', 'pw', 'app']);
  });

  it('puts a licence key, an ID number or a wallet address only in the field picked from', async () => {
    html(`<form><label for="name">Licensed to</label><input id="name"><label for="key">License key</label><input id="key">
      <label for="pp">Passport number</label><input id="pp"><button>Register</button></form>`);
    const licence: Suggestion = { kind: 'software-license', id: 's1', title: 'Editor', subtitle: 'Ada' };
    const host = start([licence], { 'license-key': 'AAAA-BBBB-CCCC', 'document-number': 'X1234', 'wallet-address': 'bc1q' });
    const items = await openMenu('key');
    expect(items).toHaveLength(1);
    items[0]!.click();
    await flush();
    expect(['name', 'key', 'pp'].map((id) => field(id).value)).toEqual(['', 'AAAA-BBBB-CCCC', '']);
    vi.mocked(host.getSuggestions).mockResolvedValue([{ kind: 'id-document', id: 'p1', title: 'Passport' }]);
    const passport = await openMenu('pp');
    passport[0]!.click();
    await flush();
    expect(['name', 'key', 'pp'].map((id) => field(id).value)).toEqual(['', 'AAAA-BBBB-CCCC', 'X1234']);
  });

  it('shows no bank account in a sign-in field, and no login in a bank field', async () => {
    html(`${UK_TRANSFER}<form><input id="u" autocomplete="username"><input id="p" type="password"><button>Log in</button></form>`);
    start([BANK, LOGIN], {});
    expect((await openMenu('sort')).map((i) => i.textContent)).toEqual([expect.stringContaining('Savings')]);
    expect((await openMenu('u')).map((i) => i.textContent)).toEqual([expect.stringContaining('Adminer')]);
  });
});
