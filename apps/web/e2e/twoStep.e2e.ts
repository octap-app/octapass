// Two-step sign-in in the browser, against the real server: turn it on with an authenticator app
// (codes computed here, as the phone would), add a security key (Chrome's virtual authenticator),
// then sign in on fresh browsers with a code, a recovery code and the key. Each step builds on the
// one before.
//
//   pnpm --filter @octapass/web e2e          (HEADED=1 to watch)

import { totpCode } from '@octapass/vault-client';
import type { BrowserContext, CDPSession, Page } from 'playwright-core';
import { startStack, type Stack } from './stack';

const PASSWORD = 'Lantern ruby quiet anchor 42';
const EMAIL = `maya-2fa-${Date.now()}@example.com`;

interface VirtualCredential {
  credentialId: string;
  isResidentCredential: boolean;
  rpId: string;
  privateKey: string;
  signCount: number;
  userHandle?: string;
}

let stack: Stack;
let context: BrowserContext;
let page: Page;
let secretKey: string;
let setupKey: string;
let recoveryCodes: string[];
let securityKey: VirtualCredential;
const contexts: BrowserContext[] = [];
const pageErrors: string[] = [];

async function newContext(): Promise<BrowserContext> {
  const next = await stack.browser.newContext({ viewport: { width: 1280, height: 860 } });
  next.on('weberror', (error) => pageErrors.push(error.error().message));
  contexts.push(next);
  return next;
}

/** A USB security key: no user verification, touched as soon as it's asked. */
async function addSecurityKeyAuthenticator(target: Page): Promise<{ cdp: CDPSession; authenticatorId: string }> {
  const cdp = await target.context().newCDPSession(target);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', transport: 'usb', hasResidentKey: false, hasUserVerification: false, automaticPresenceSimulation: true },
  });
  return { cdp, authenticatorId };
}

/** The current code, or one a step ahead: the server takes each step once, and turning on used the current one. */
const code = async (stepsAhead = 0) => (await totpCode(setupKey, Date.now() + stepsAhead * 30_000)).code;

async function signInToSecondStep(target: Page): Promise<void> {
  await target.goto(`${stack.webUrl}/welcome`);
  await target.getByRole('textbox', { name: 'Email' }).fill(EMAIL);
  await target.getByRole('textbox', { name: 'Master password' }).fill(PASSWORD);
  await target.getByRole('textbox', { name: 'Secret Key' }).fill(secretKey);
  await target.getByRole('button', { name: 'Sign in' }).click();
  await target.getByRole('heading', { name: 'Two-step sign-in' }).waitFor();
}

async function openSettings(target: Page): Promise<void> {
  await target.getByRole('link', { name: 'Settings' }).click();
  await target.getByRole('heading', { name: 'Settings', level: 1 }).waitFor();
}

beforeAll(async () => {
  stack = await startStack();
  context = await newContext();
  page = await context.newPage();
});

afterAll(async () => {
  await stack?.stop();
});

afterEach(() => {
  expect(pageErrors, 'uncaught errors in the page').toEqual([]);
});

describe('two-step sign-in on the real server', () => {
  it('signs up', async () => {
    await page.goto(`${stack.webUrl}/signup`);
    await page.getByRole('textbox', { name: 'Email' }).fill(EMAIL);
    await page.getByRole('textbox', { name: 'Master password', exact: true }).fill(PASSWORD);
    await page.getByRole('textbox', { name: 'Confirm master password' }).fill(PASSWORD);
    await page.getByRole('button', { name: 'Continue' }).click();
    const devCode = (await page.getByRole('status').filter({ hasText: 'Development server' }).locator('strong').innerText()).trim();
    await page.getByRole('textbox', { name: 'Verification code' }).fill(devCode);
    await page.getByRole('button', { name: 'Verify email' }).click();
    const kit = page.getByRole('article', { name: 'Octa Pass Recovery Kit' });
    await kit.waitFor();
    secretKey = (await kit.getByRole('definition').nth(2).innerText()).trim();
    await page.getByRole('checkbox', { name: /saved my Recovery Kit/ }).check();
    await page.getByRole('button', { name: 'Continue' }).click();
    await page.getByRole('button', { name: 'Open my vault' }).click();
    await page.getByRole('heading', { name: 'Nothing here yet' }).waitFor();
  });

  it('turns on with the master password, a QR code and a code, and shows the recovery codes once', async () => {
    await openSettings(page);
    const section = page.getByRole('region', { name: 'Two-step sign-in' });
    await section.getByRole('button', { name: 'Turn on' }).click();
    const dialog = page.getByRole('dialog', { name: 'Turn on two-step sign-in' });
    await dialog.getByRole('textbox', { name: 'Master password' }).fill(PASSWORD);
    await dialog.getByRole('button', { name: 'Continue' }).click();

    await dialog.getByRole('img', { name: 'QR code for your authenticator app' }).waitFor();
    setupKey = (await dialog.getByLabel('Setup key', { exact: true }).innerText()).replace(/\s/g, '');
    expect(setupKey).toMatch(/^[A-Z2-7]{16,}$/);
    const field = dialog.getByRole('textbox', { name: 'Authenticator code' });
    expect(await field.getAttribute('autocomplete')).toBe('one-time-code');
    await field.fill(await code());
    await dialog.getByRole('button', { name: 'Turn on' }).click();

    const list = dialog.getByRole('list', { name: 'Recovery codes' });
    await list.waitFor();
    recoveryCodes = (await list.getByRole('listitem').allInnerTexts()).map((c) => c.trim());
    expect(recoveryCodes).toHaveLength(10);
    await dialog.getByRole('checkbox', { name: 'I’ve saved these codes' }).check();
    await dialog.getByRole('button', { name: 'Done' }).click();
    await section.getByText('10 codes left', { exact: false }).waitFor();
  });

  it('adds a security key', async () => {
    const { cdp, authenticatorId } = await addSecurityKeyAuthenticator(page);
    const section = page.getByRole('region', { name: 'Two-step sign-in' });
    await section.getByRole('button', { name: 'Add security key' }).click();
    const dialog = page.getByRole('dialog', { name: 'Add security key' });
    await dialog.getByRole('textbox', { name: 'Name' }).fill('Blue key');
    await dialog.getByRole('textbox', { name: 'Master password' }).fill(PASSWORD);
    await dialog.getByRole('button', { name: 'Add security key' }).click();
    await section.getByRole('list', { name: 'Security keys' }).getByText('Blue key').waitFor();

    const { credentials } = (await cdp.send('WebAuthn.getCredentials', { authenticatorId })) as { credentials: VirtualCredential[] };
    expect(credentials).toHaveLength(1);
    securityKey = credentials[0]!;
  });

  it('a fresh browser needs the code after the password', async () => {
    await openSettings(page);
    await page.getByRole('button', { name: 'Sign out', exact: true }).click();
    await page.getByRole('heading', { name: 'Welcome back' }).waitFor();

    const fresh = await (await newContext()).newPage();
    await signInToSecondStep(fresh);
    await fresh.getByRole('textbox', { name: 'Authenticator code' }).fill('000000');
    await fresh.getByRole('button', { name: 'Verify' }).click();
    await fresh.getByText(/That code isn’t right/).waitFor();
    await fresh.getByRole('textbox', { name: 'Authenticator code' }).fill(await code(1));
    await fresh.getByRole('button', { name: 'Verify' }).click();
    await fresh.getByRole('heading', { name: 'Nothing here yet' }).waitFor();
  });

  it('a recovery code works instead, once', async () => {
    const fresh = await (await newContext()).newPage();
    await signInToSecondStep(fresh);
    await fresh.getByRole('button', { name: 'Use a recovery code' }).click();
    await fresh.getByRole('textbox', { name: 'Recovery code' }).fill(recoveryCodes[0]!);
    await fresh.getByRole('button', { name: 'Verify' }).click();
    await fresh.getByRole('heading', { name: 'Nothing here yet' }).waitFor();

    const again = await (await newContext()).newPage();
    await signInToSecondStep(again);
    await again.getByRole('button', { name: 'Use a recovery code' }).click();
    await again.getByRole('textbox', { name: 'Recovery code' }).fill(recoveryCodes[0]!);
    await again.getByRole('button', { name: 'Verify' }).click();
    await again.getByText(/That code isn’t right/).waitFor();
  });

  it('the security key works on another browser that has it', async () => {
    const fresh = await (await newContext()).newPage();
    await signInToSecondStep(fresh);
    const { cdp, authenticatorId } = await addSecurityKeyAuthenticator(fresh);
    await cdp.send('WebAuthn.addCredential', { authenticatorId, credential: securityKey });
    await fresh.getByRole('button', { name: 'Use a security key' }).click();
    await fresh.getByRole('heading', { name: 'Nothing here yet' }).waitFor();

    await openSettings(fresh);
    const keys = fresh.getByRole('region', { name: 'Two-step sign-in' }).getByRole('list', { name: 'Security keys' });
    await keys.getByText(/Last used/).waitFor();
  });
});
