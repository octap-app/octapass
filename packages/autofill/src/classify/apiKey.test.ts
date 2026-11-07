import { classifyFields } from './form';
import { credentialHint, pastedToken, recognizeApiKey, type ApiKeyKind } from './apiKey';
import { html, stubLayout } from '../test/layout';
import { isCandidate } from './field';

// Every value here is made up: repeated FAKE text in the shape of a key, never a real one.
const fake = 'FAKE0fake1'.repeat(6);
const jwt = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.${btoa('{"sub":"fake"}').replaceAll('=', '')}.${fake}`;

describe('recognizeApiKey', () => {
  const known: [ApiKeyKind, string][] = [
    ['github', `ghp_${fake.slice(0, 36)}`],
    ['github', `gho_${fake.slice(0, 36)}`],
    ['github', `ghs_${fake.slice(0, 36)}`],
    ['github', `github_pat_${fake.slice(0, 30)}_${fake.slice(0, 30)}`],
    ['stripe', `sk_live_${fake.slice(0, 24)}`],
    ['stripe', `sk_test_${fake.slice(0, 24)}`],
    ['stripe', `rk_live_${fake.slice(0, 24)}`],
    ['aws', 'AKIAFAKE0123456TEST9'],
    ['slack', 'xoxb-000000000000-FAKEFAKEFAKE'],
    ['npm', `npm_${fake.slice(0, 36)}`],
    ['anthropic', `sk-ant-api03-${fake}`],
    ['openai', `sk-${fake}`],
    ['openai', `sk-proj-${fake}`],
    ['gitlab', `glpat-${fake.slice(0, 20)}`],
    ['sendgrid', `SG.${fake.slice(0, 22)}.${fake.slice(0, 43)}`],
    ['google', `AIza${fake.slice(0, 35)}`],
    ['jwt', jwt],
    ['octapass-service-account', `opsa1_${fake}`],
    ['octapass-connect', `opc1_${fake.slice(0, 32)}`],
  ];

  it.each(known)('recognises %s from its shape, with no hint from the field: %s', (kind, value) => {
    expect(recognizeApiKey(value, false)).toBe(kind);
  });

  it.each([
    'correct-horse-battery-staple',
    'hello',
    'not.a.jwt',
    '1.2.3',
    'eyJ.eyJ.abc',
    // eyJ… parts, but the header names no algorithm.
    `${btoa('{"typ":"JWT"}').replaceAll('=', '')}.${btoa('{"sub":"fake"}').replaceAll('=', '')}.${fake}`,
    'sk-this-is-a-project-slug-with-many-plain-words',
    'sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
    `sk_${'test'}_${'x'.repeat(24)}`, // split so secret scanners don't flag the placeholder
    'pk_live_FAKE0fake1FAKE0fake1FAKE',
    'ghp_short',
    'AKIA123',
    'https://github.com/octapass/octapass',
    'FAKE0TEST1VALUE2NOT3REAL4TOKEN5XYZ',
    'd41d8cd98f00b204e9800998ecf8427e',
  ])('leaves %s alone when the field says nothing', (value) => {
    expect(recognizeApiKey(value, false)).toBeUndefined();
  });

  it.each(['FAKE0TEST1VALUE2NOT3REAL4TOKEN5XYZ', 'd41d8cd98f00b204e9800998ecf8427e', '550e8400-e29b-41d4-a716-446655440000', 'c2VjcmV0LWJ1dC1mYWtlLTAxMjM0NTY3ODk='])(
    'takes %s as a key when the field says it is one',
    (value) => {
      expect(recognizeApiKey(value, true)).toBe('generic');
    },
  );

  it.each([
    'my-project-2024-staging-environment',
    'test_token_value_1234567890',
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1',
    '1234567890123456789012345678901234',
    'abcdefghijklmnopqrstuvwxyzabcdefgh',
    'https://example.com/webhook/123456789',
    'octapass://Personal/GitHub/token',
    'short1',
    '2026-11-02T10:00:00.000Z',
    'password123password123password123',
  ])('stays conservative in a key field: %s', (value) => {
    expect(recognizeApiKey(value, true)).toBeUndefined();
  });
});

describe('pastedToken', () => {
  it('takes one token, trimmed, without Bearer', () => {
    expect(pastedToken('  abc123\n')).toBe('abc123');
    expect(pastedToken('Bearer abc123')).toBe('abc123');
    expect(pastedToken('token abc123')).toBe('abc123');
  });

  it.each([['ordinary prose'], ['Thanks for your help with this!'], ['API_KEY=abc\nOTHER=def'], ['two words'], [''], ['   '], ['x'.repeat(9000)]])('refuses %j', (text) => {
    expect(pastedToken(text)).toBeUndefined();
  });
});

describe('credentialHint', () => {
  it.each(['api key', 'API-Key', 'api_key', 'apikey', 'x api key', 'API token', 'Your token', 'Secret', 'client secret', 'Bearer token', 'Authorization', 'Personal access token', 'Secret access key', 'مفتاح API'])(
    'says %s takes a key',
    (text) => {
      expect(credentialHint(text)).toBe(true);
    },
  );

  it.each(['Token name', 'API key name', 'Secret ID', 'Token URL', 'Token endpoint', 'Token expiry', 'Key description', 'CSRF token', 'Verification token', 'Password reset token', 'Secret question', 'Authorization code', 'Card token'])(
    'isn’t fooled by %s',
    (text) => {
      expect(credentialHint(text)).not.toBe(true);
    },
  );

  it.each(['Email', 'Secretary', 'Tokenize', 'Key', 'License key', 'Search key', 'Message'])('has nothing to say about %s', (text) => {
    expect(credentialHint(text)).toBeUndefined();
  });
});

describe('field classification', () => {
  let restore: () => void;
  beforeEach(() => {
    restore = stubLayout();
  });
  afterEach(() => restore());

  const typed = (markup: string, id = 'f') => {
    html(markup);
    const forms = classifyFields([...document.querySelectorAll('input, textarea, select')].filter(isCandidate));
    const form = forms.find((f) => f.fields.some((field) => field.element.id === id))!;
    return { type: form.fields.find((field) => field.element.id === id)!.type, form: form.type };
  };

  it.each([
    ['a named input', '<form><input id="f" name="api_key"><button>Save</button></form>'],
    ['a masked key field', '<form><label>API key <input id="f" type="password"></label><button>Connect</button></form>'],
    ['a textarea', '<form><label for="f">Secret</label><textarea id="f"></textarea><button>Add secret</button></form>'],
    ['a placeholder', '<form><input id="f" placeholder="Paste your bearer token"><button>Send</button></form>'],
    ['a label on name="token"', '<form><label>API token <input id="f" name="token"></label><button>Authorize</button></form>'],
  ])('takes %s', (_name, markup) => {
    expect(typed(markup).type).toBe('api-credential');
  });

  it('leaves a sign-in form’s password alone, whatever it’s called', () => {
    expect(typed('<form><input name="user" autocomplete="username"><label>API key <input id="f" type="password"></label><button>Sign in</button></form>')).toEqual({ type: 'current-password', form: 'login' });
    expect(typed('<form><label>Token <input id="f" type="password" name="token"></label><button>Sign in</button></form>').type).toBe('current-password');
    expect(typed('<form><input type="email" name="email"><label>Secret <input id="f" type="password"></label><button>Continue</button></form>').type).not.toBe('api-credential');
  });

  it('keeps a 2FA box a one-time code', () => {
    expect(typed('<form><input id="f" name="token"><button>Sign in</button></form>').type).toBe('one-time-code');
    expect(typed('<form><h1>Two-factor authentication</h1><label>Token <input id="f" name="token"></label><button>Continue</button></form>').type).toBe('one-time-code');
    expect(typed('<form><label>Token <input id="f" name="token"></label><button>Verify</button></form>').type).toBe('one-time-code');
    expect(typed('<form><label>Token <input id="f" name="token" maxlength="6"></label><button>Save</button></form>').type).not.toBe('api-credential');
    expect(typed('<form><label>Token <input id="f" inputmode="numeric"></label><button>Save</button></form>').type).not.toBe('api-credential');
  });

  it.each([
    ['a field about the token', '<form><label>Token name <input id="f" name="token"></label><button>Generate token</button></form>'],
    ['a forgery token', '<form><input id="f" type="hidden" name="csrf_token"><button>Save</button></form>'],
    ['a plain field', '<form><label>Title <input id="f"></label><button>Save</button></form>'],
    ['a password labelled so', '<form><label>Password or token <input id="f" type="password"></label><button>Save</button></form>'],
    ['a select', '<form><label>Token <select id="f"><option>a</option></select></label></form>'],
  ])('doesn’t take %s', (_name, markup) => {
    expect(typed(markup).type).not.toBe('api-credential');
  });
});
