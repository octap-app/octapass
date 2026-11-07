import { isVaultError } from '../errors';
import type { DocumentDetails, LoginDetails } from '../types';
import { installFakeAuthenticator } from './fakeAuthenticator';
import { DEFAULT_SERVER_URL, MockVaultService, PASSWORD_RECHECK_MS } from './MockVaultService';

let db = 0;
const serverUrl = DEFAULT_SERVER_URL;
const password = 'Lantern ruby quiet anchor';

async function create(options = {}) {
  return MockVaultService.create({ dbName: `test-${db++}`, latency: [0, 0], fetch: async () => new Response(''), ...options });
}

async function signedUp(service?: MockVaultService) {
  const s = service ?? (await create());
  const { signupId, devVerificationCode } = await s.startSignup({ serverUrl, email: ' Maya@Example.com ', password });
  const { recoveryKit } = await s.finishSignup({ signupId, verificationCode: devVerificationCode! });
  return { service: s, recoveryKit };
}

async function expectCode(promise: Promise<unknown>, code: Parameters<typeof isVaultError>[1]) {
  const error = await promise.then(() => undefined, (e: unknown) => e);
  expect(isVaultError(error, code)).toBe(true);
}

describe('MockVaultService accounts', () => {
  it('signs up with a verification code and returns a Recovery Kit', async () => {
    const { service, recoveryKit } = await signedUp();
    expect(recoveryKit.email).toBe('maya@example.com');
    expect(recoveryKit.secretKey).toMatch(/^OP1-/);
    expect(service.getSession()).toEqual({ status: 'unlocked', email: 'maya@example.com', serverUrl, confirmed: true });
    expect((await service.listItems()).length).toBeGreaterThan(10);
  });

  it('rejects a wrong verification code and a taken email', async () => {
    const service = await create();
    const { signupId } = await service.startSignup({ serverUrl, email: 'a@example.com', password });
    await expectCode(service.finishSignup({ signupId, verificationCode: '000000x' }), 'invalidVerificationCode');
    await signedUp(service);
    await expectCode(service.startSignup({ serverUrl, email: 'maya@example.com', password }), 'emailTaken');
  });

  it('refuses plain http servers except localhost', async () => {
    const service = await create();
    await expectCode(service.getServerInfo('http://vault.example.com'), 'insecureServerUrl');
    await expect(service.getServerInfo('http://localhost:8080')).resolves.toMatchObject({ apiVersion: 1 });
    await expectCode(service.getServerInfo('https://nowhere.invalid'), 'serverUnreachable');
  });

  it('locks, then unlocks only with the master password', async () => {
    const { service } = await signedUp();
    service.lock();
    expect(service.getSession().status).toBe('locked');
    // A lock ends what the unlock covered (plan 03 History, 2026-11-05).
    expect(service.getSession().confirmed).toBeUndefined();
    await expectCode(service.listItems(), 'locked');
    await expectCode(service.unlock('wrong'), 'invalidCredentials');
    await service.unlock(password);
    expect(service.getSession()).toMatchObject({ status: 'unlocked', confirmed: true });
  });

  it('comes back locked after a reload, with the data intact', async () => {
    const dbName = `test-${db++}`;
    const { service } = await signedUp(await create({ dbName }));
    const count = (await service.listItems()).length;

    const reloaded = await create({ dbName });
    expect(reloaded.getSession().status).toBe('locked');
    await reloaded.unlock(password);
    expect(await reloaded.listItems()).toHaveLength(count);
  });

  it('needs the Secret Key to sign in again after signing out', async () => {
    const { service, recoveryKit } = await signedUp();
    await service.signOut();
    expect(service.rememberedAccounts()).toEqual([]);
    await expectCode(service.signIn({ serverUrl, email: 'maya@example.com', password }), 'secretKeyRequired');
    await expectCode(service.signIn({ serverUrl, email: 'maya@example.com', password, secretKey: 'nonsense' }), 'invalidSecretKey');
    await service.signIn({ serverUrl, email: 'MAYA@example.com', password, secretKey: recoveryKit.secretKey.toLowerCase() });
    expect(service.getSession().status).toBe('unlocked');
    expect(service.rememberedAccounts()).toEqual([{ email: 'maya@example.com', serverUrl }]);
  });
});

describe('MockVaultService account deletion', () => {
  it('summarises what will be deleted', async () => {
    const { service } = await signedUp();
    const summary = await service.getAccountSummary();
    expect(summary).toMatchObject({ email: 'maya@example.com', vaultCount: 3, deviceCount: 3, sharedVaultsOwned: ['Family'] });
    expect(summary.itemCount).toBe((await service.listItems()).length);
  });

  it('keeps everything when the email or password is wrong', async () => {
    const { service } = await signedUp();
    await expectCode(service.deleteAccount({ confirmEmail: 'someone@example.com', password }), 'emailMismatch');
    await expectCode(service.deleteAccount({ confirmEmail: 'maya@example.com', password: 'wrong' }), 'invalidCredentials');
    expect(service.getSession().status).toBe('unlocked');
    expect((await service.listItems()).length).toBeGreaterThan(0);
  });

  it('deletes the account, wipes this device and frees the email', async () => {
    const dbName = `test-${db++}`;
    const { service, recoveryKit } = await signedUp(await create({ dbName }));
    await service.deleteAccount({ confirmEmail: ' MAYA@example.com ', password });

    expect(service.getSession()).toEqual({ status: 'signedOut' });
    expect(service.rememberedAccounts()).toEqual([]);
    await expectCode(service.listItems(), 'locked');
    await expectCode(service.signIn({ serverUrl, email: 'maya@example.com', password, secretKey: recoveryKit.secretKey }), 'invalidCredentials');

    const reloaded = await create({ dbName });
    expect(reloaded.getSession().status).toBe('signedOut');
    await expect(signedUp(reloaded)).resolves.toBeDefined();
  });
});

describe('MockVaultService master password', () => {
  const newPassword = 'Copper meadow lantern swift';

  it('changes it after checking the current one', async () => {
    const { service } = await signedUp();
    await expectCode(service.changeMasterPassword({ currentPassword: 'wrong', newPassword }), 'invalidCredentials');
    await service.changeMasterPassword({ currentPassword: password, newPassword });
    service.lock();
    await expectCode(service.unlock(password), 'invalidCredentials');
    await service.unlock(newPassword);
    expect((await service.sharing.getSecurityLog()).map((e) => e.type)).toContain('password-changed');
  });

  it('resets it with the emailed code and the recovery code, then gives a new recovery code', async () => {
    const { service, recoveryKit } = await signedUp();
    service.lock();
    const { resetId, devVerificationCode } = await service.startPasswordReset({ serverUrl, email: 'maya@example.com' });
    await expectCode(service.finishPasswordReset({ resetId, recoveryCode: recoveryKit.recoveryCode, password: newPassword }), 'resetExpired');
    await expectCode(service.verifyPasswordReset({ resetId, verificationCode: '000000x' }), 'invalidVerificationCode');
    await service.verifyPasswordReset({ resetId, verificationCode: devVerificationCode! });
    await expectCode(service.finishPasswordReset({ resetId, recoveryCode: 'AAAAA-BBBBB', password: newPassword }), 'invalidRecoveryCode');

    const reset = await service.finishPasswordReset({ resetId, recoveryCode: recoveryKit.recoveryCode, password: newPassword });
    expect(reset.signIn).toEqual({ status: 'signedIn' });
    expect(reset.recoveryKit.secretKey).toBe(recoveryKit.secretKey);
    expect(reset.recoveryKit.recoveryCode).not.toBe(recoveryKit.recoveryCode);
    expect(service.getSession().status).toBe('unlocked');
    expect((await service.sharing.getSecurityLog()).map((e) => e.type)).toContain('password-reset');
    await expectCode(service.verifyPasswordReset({ resetId, verificationCode: devVerificationCode! }), 'resetExpired');
  });
});

describe('MockVaultService device unlock', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it('unlocks with the device after enabling it, and stores nothing new on the server', async () => {
    const auth = installFakeAuthenticator();
    const { service } = await signedUp();
    expect(await service.getUnlockMethods()).toMatchObject({ deviceUnlockSupported: true, deviceUnlockEnabled: false });

    await service.enableDeviceUnlock();
    expect(await service.getUnlockMethods()).toMatchObject({ deviceUnlockEnabled: true, passwordRequired: false });
    service.lock();
    await service.unlockWithDevice();
    expect(service.getSession()).toMatchObject({ status: 'unlocked', confirmed: true });
    expect((await service.listItems()).length).toBeGreaterThan(0);
    expect(auth.get).toHaveBeenCalledTimes(2);
  });

  it('survives a reload: the record lives in this browser', async () => {
    installFakeAuthenticator();
    const dbName = `test-${db++}`;
    const { service } = await signedUp(await create({ dbName }));
    await service.enableDeviceUnlock();

    const reloaded = await create({ dbName });
    expect(reloaded.getSession().status).toBe('locked');
    await reloaded.unlockWithDevice();
    expect(reloaded.getSession().status).toBe('unlocked');
  });

  it('asks for the master password every 14 days, and a password unlock resets the clock', async () => {
    installFakeAuthenticator();
    const { service } = await signedUp();
    await service.enableDeviceUnlock();
    service.lock();

    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(Date.now() + PASSWORD_RECHECK_MS + 60_000);
    expect((await service.getUnlockMethods()).passwordRequired).toBe(true);
    await expectCode(service.unlockWithDevice(), 'passwordRequired');

    await service.unlock(password);
    service.lock();
    expect((await service.getUnlockMethods()).passwordRequired).toBe(false);
    await service.unlockWithDevice();
    expect(service.getSession().status).toBe('unlocked');
  });

  it('keeps the vault locked when the prompt is dismissed', async () => {
    const auth = installFakeAuthenticator();
    const { service } = await signedUp();
    await service.enableDeviceUnlock();
    service.lock();
    auth.cancelNext();
    await expectCode(service.unlockWithDevice(), 'deviceUnlockCancelled');
    expect(service.getSession().status).toBe('locked');
  });

  it('says so plainly when the browser has no PRF support', async () => {
    installFakeAuthenticator({ prf: false });
    const { service } = await signedUp();
    await expectCode(service.enableDeviceUnlock(), 'deviceUnlockUnsupported');
    expect((await service.getUnlockMethods()).deviceUnlockEnabled).toBe(false);
  });

  it('forgets device unlock when disabled, on sign-out and on account deletion', async () => {
    installFakeAuthenticator();
    const { service, recoveryKit } = await signedUp();
    await service.enableDeviceUnlock();
    await service.disableDeviceUnlock();
    expect((await service.getUnlockMethods()).deviceUnlockEnabled).toBe(false);

    await service.enableDeviceUnlock();
    await service.signOut();
    await service.signIn({ serverUrl, email: 'maya@example.com', password, secretKey: recoveryKit.secretKey });
    expect((await service.getUnlockMethods()).deviceUnlockEnabled).toBe(false);

    await service.enableDeviceUnlock();
    await service.deleteAccount({ confirmEmail: 'maya@example.com', password });
    expect((await service.getUnlockMethods()).deviceUnlockEnabled).toBe(false);
  });

  it('can’t reset the 14-day clock by turning device unlock off and on', async () => {
    installFakeAuthenticator();
    const { service } = await signedUp();
    await service.enableDeviceUnlock();
    service.lock();
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(Date.now() + 10 * 86_400_000);
    await service.unlockWithDevice();
    await service.disableDeviceUnlock();
    await service.enableDeviceUnlock();
    service.lock();
    vi.setSystemTime(Date.now() + 5 * 86_400_000);
    expect((await service.getUnlockMethods()).passwordRequired).toBe(true);
  });

  it('doesn’t enable device unlock if the vault locks during the prompts', async () => {
    installFakeAuthenticator();
    const { service } = await signedUp();
    const enabling = service.enableDeviceUnlock();
    service.lock();
    await expectCode(enabling, 'locked');
    expect((await service.getUnlockMethods()).deviceUnlockEnabled).toBe(false);
  });

  it('can only be enabled while unlocked', async () => {
    installFakeAuthenticator();
    const { service } = await signedUp();
    service.lock();
    await expectCode(service.enableDeviceUnlock(), 'locked');
  });
});

describe('MockVaultService items', () => {
  it('creates, edits with password history, trashes and restores', async () => {
    const { service } = await signedUp();
    const [personal] = await service.listVaults();
    const changes = vi.fn();
    service.onItemsChange(changes);

    const created = await service.saveItem({
      vaultId: personal!.id,
      overview: { schemaVersion: 1, type: 'login', title: 'Kagi', urls: ['https://kagi.com'], futureField: 'kept' } as never,
      details: { schemaVersion: 1, username: 'maya', password: 'first' },
    });
    expect(created.revision).toBe(1);

    const edited = await service.saveItem({ ...created, details: { ...(created.details as LoginDetails), password: 'second' } });
    expect(edited.revision).toBe(2);
    expect((edited.details as LoginDetails).passwordHistory?.[0]?.password).toBe('first');
    expect((edited.overview as unknown as Record<string, unknown>).futureField).toBe('kept');

    await service.deleteItem(created.id);
    expect((await service.listItems({ query: 'kagi' })).length).toBe(0);
    expect((await service.listItems({ trash: true })).map((i) => i.id)).toEqual([created.id]);
    await service.restoreItem(created.id);
    expect((await service.listItems({ query: 'kagi' })).length).toBe(1);
    expect(changes).toHaveBeenCalled();
  });

  it('refuses a save when the vault locks before it lands, and keeps the stored vault intact', async () => {
    const { service } = await signedUp();
    const [first] = await service.listItems();
    const item = await service.getItem(first!.id);
    const saving = service.saveItem({ ...item, overview: { ...item.overview, title: 'Changed' } });
    service.lock();
    await expectCode(saving, 'locked');
    await service.unlock(password);
    expect((await service.getItem(item.id)).overview.title).toBe(item.overview.title);
  });

  it('saves a conflicting copy when the draft is based on an old revision', async () => {
    const { service } = await signedUp();
    const [first] = await service.listItems();
    const item = await service.getItem(first!.id);
    await service.saveItem({ ...item, overview: { ...item.overview, title: 'Changed elsewhere' } });
    const copy = await service.saveItem({ ...item, overview: { ...item.overview, title: 'Mine' } });
    expect(copy.id).not.toBe(item.id);
    expect(copy.overview.title).toBe('Mine (conflicting copy)');
  });

  it('filters by vault, type, favourites and passkeys', async () => {
    const { service } = await signedUp();
    const vaults = await service.listVaults();
    const family = vaults.find((v) => v.type === 'shared')!;
    expect((await service.listItems({ vaultId: family.id })).every((i) => i.vaultId === family.id)).toBe(true);
    expect((await service.listItems({ type: 'card' })).every((i) => i.type === 'card')).toBe(true);
    expect((await service.listItems({ favorites: true })).every((i) => i.favorite)).toBe(true);
    expect((await service.listItems({ passkeys: true })).length).toBeGreaterThan(0);
  });

  it('imports a Chrome CSV into the personal vault and exports JSON', async () => {
    const { service } = await signedUp();
    const csv = 'name,url,username,password,note\nExample,https://example.org,maya,pa55word,\n';
    const result = await service.importFile('chrome', new File([csv], 'chrome.csv'));
    expect(result.imported).toBe(1);
    const json = JSON.parse(await (await service.exportVault('json')).text());
    expect(json.items.some((i: { overview: { title: string } }) => i.overview.title === 'Example')).toBe(true);
  });

  it('reports health problems in the demo vault', async () => {
    const { service } = await signedUp();
    const report = await service.getHealthReport();
    expect(report.weak.length).toBeGreaterThan(0);
    expect(report.reused.length).toBeGreaterThan(0);
    expect(report.missing2fa.length).toBeGreaterThan(0);
    expect(report.score).toBeLessThan(100);
  });
});

describe('MockVaultService attachments', () => {
  it('adds, reads and removes files, keeps them through edits, and checks the limits', async () => {
    const { service } = await signedUp();
    const [vault] = await service.listVaults();
    const item = await service.saveItem({ vaultId: vault!.id, overview: { schemaVersion: 1, title: 'Lease', type: 'document' }, details: { schemaVersion: 1 } });
    const added = await service.addAttachment(item.id, new Blob(['contract'], { type: 'text/plain' }), 'lease.txt');
    const [file] = (added.details as DocumentDetails).attachments!;
    expect(file).toMatchObject({ name: 'lease.txt', type: 'text/plain', size: 8 });
    expect(await (await service.getAttachment(item.id, file!.id)).text()).toBe('contract');
    expect((await service.getStorageUsage()).attachmentBytes).toBe(8);

    const edited = await service.saveItem({ ...added, overview: { ...added.overview, title: 'Lease 2026' }, details: { schemaVersion: 1 } });
    expect((edited.details as DocumentDetails).attachments).toEqual([file]);

    await expectCode(service.addAttachment(item.id, new Blob([new Uint8Array(100 * 1024 ** 2 + 1)]), 'big.bin'), 'fileTooLarge');
    const removed = await service.removeAttachment(item.id, file!.id);
    expect((removed.details as DocumentDetails).attachments).toBeUndefined();
    await expectCode(service.getAttachment(item.id, file!.id), 'notFound');
  });
});
