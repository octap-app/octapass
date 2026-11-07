// A new master password against the real server: changed while signed in, and reset with the
// recovery code from the Recovery Kit.
// Run with `pnpm --filter @octapass/vault-client test:server`.

import { device, expectCode, PASSWORD, signedUp } from './testing/devices';
import { startServer, type TestServer } from './testing/server';

const NEW_PASSWORD = 'Copper meadow lantern swift 77';
let server: TestServer;

beforeAll(async () => {
  server = await startServer();
});
afterAll(() => server?.stop());

const login = (title: string) => ({ overview: { schemaVersion: 1 as const, type: 'login' as const, title }, details: { schemaVersion: 1 as const, username: 'me', password: 'pw' } });

describe('changing the master password', () => {
  it('checks the current one, keeps this device and signs out the others', async () => {
    const laptop = await signedUp(server.url);
    const phone = await device();
    await phone.service.signIn({ serverUrl: server.url, email: laptop.email, password: PASSWORD, secretKey: laptop.secretKey });

    await expectCode(laptop.service.changeMasterPassword({ currentPassword: 'wrong password', newPassword: NEW_PASSWORD }), 'invalidCredentials');
    await laptop.service.changeMasterPassword({ currentPassword: PASSWORD, newPassword: NEW_PASSWORD });
    expect(laptop.service.getSession().status).toBe('unlocked');
    expect((await laptop.service.getSecurityLog()).map((e) => e.type)).toContain('password-changed');

    // This device unlocks with the new password only, and confirms with it from now on.
    laptop.service.lock();
    await expectCode(laptop.service.unlock(PASSWORD), 'invalidCredentials');
    await laptop.service.unlock(NEW_PASSWORD);
    expect(laptop.service.getSession().status).toBe('unlocked');
    await expectCode(laptop.service.changeMasterPassword({ currentPassword: PASSWORD, newPassword: 'x' }), 'invalidCredentials');

    // The phone was signed out; it signs in again with the new password and the same Secret Key.
    phone.service.lock();
    await expectCode(phone.service.signIn({ serverUrl: server.url, email: laptop.email, password: PASSWORD }), 'invalidCredentials');
    expect(await phone.service.signIn({ serverUrl: server.url, email: laptop.email, password: NEW_PASSWORD })).toEqual({ status: 'signedIn' });
  });
});

describe('resetting the master password with the recovery code', () => {
  it('needs the emailed code and the recovery code, keeps the vault and gives a new Recovery Kit', async () => {
    const laptop = await signedUp(server.url);
    await laptop.service.saveItem({ vaultId: (await laptop.service.listVaults())[0]!.id, ...login('Kept') });
    const other = await signedUp(server.url);

    // A device that never saw the account: it gets a new Secret Key too.
    const fresh = await device();
    const { resetId, devVerificationCode } = await fresh.service.startPasswordReset({ serverUrl: server.url, email: laptop.email });
    await expectCode(fresh.service.finishPasswordReset({ resetId, recoveryCode: laptop.recoveryCode!, password: NEW_PASSWORD }), 'resetExpired');
    await expectCode(fresh.service.verifyPasswordReset({ resetId, verificationCode: '000000' }), 'invalidVerificationCode');
    await fresh.service.verifyPasswordReset({ resetId, verificationCode: devVerificationCode! });
    await expectCode(fresh.service.finishPasswordReset({ resetId, recoveryCode: other.recoveryCode!, password: NEW_PASSWORD }), 'invalidRecoveryCode');
    await expectCode(fresh.service.finishPasswordReset({ resetId, recoveryCode: 'not a code', password: NEW_PASSWORD }), 'invalidRecoveryCode');

    const { recoveryKit, signIn } = await fresh.service.finishPasswordReset({ resetId, recoveryCode: laptop.recoveryCode!, password: NEW_PASSWORD });
    expect(signIn).toEqual({ status: 'signedIn' });
    expect(recoveryKit).toMatchObject({ email: laptop.email, serverUrl: server.url });
    expect(recoveryKit.secretKey).not.toBe(laptop.secretKey);
    expect(recoveryKit.recoveryCode).not.toBe(laptop.recoveryCode!);
    expect((await fresh.service.listItems()).map((i) => i.title)).toEqual(['Kept']);
    expect((await fresh.service.getSecurityLog()).map((e) => e.type)).toContain('password-reset');
    await expectCode(fresh.service.verifyPasswordReset({ resetId, verificationCode: devVerificationCode! }), 'resetExpired');

    // The old password and Secret Key are gone; the new kit signs in anywhere.
    const elsewhere = await device();
    await expectCode(elsewhere.service.signIn({ serverUrl: server.url, email: laptop.email, password: NEW_PASSWORD, secretKey: laptop.secretKey }), 'invalidCredentials');
    expect(await elsewhere.service.signIn({ serverUrl: server.url, email: laptop.email, password: NEW_PASSWORD, secretKey: recoveryKit.secretKey })).toEqual({
      status: 'signedIn',
    });

    // So does the new recovery code, and the old one no longer does.
    const again = await elsewhere.service.startPasswordReset({ serverUrl: server.url, email: laptop.email });
    await elsewhere.service.verifyPasswordReset({ resetId: again.resetId, verificationCode: again.devVerificationCode! });
    await expectCode(elsewhere.service.finishPasswordReset({ resetId: again.resetId, recoveryCode: laptop.recoveryCode!, password: PASSWORD }), 'invalidRecoveryCode');
    const second = await elsewhere.service.finishPasswordReset({ resetId: again.resetId, recoveryCode: recoveryKit.recoveryCode, password: PASSWORD });
    // This device remembers the account now, so the Secret Key stays.
    expect(second.recoveryKit.secretKey).toBe(recoveryKit.secretKey);
  });
});

describe('replacing the Secret Key', () => {
  it('keeps the password, the vault and this device, and other devices need the new key', async () => {
    const laptop = await signedUp(server.url);
    await laptop.service.saveItem({ vaultId: (await laptop.service.listVaults())[0]!.id, ...login('Kept') });
    const phone = await device();
    await phone.service.signIn({ serverUrl: server.url, email: laptop.email, password: PASSWORD, secretKey: laptop.secretKey });

    await expectCode(laptop.service.rotateSecretKey!({ password: 'wrong password', newRecoveryCode: false }), 'invalidCredentials');
    const kit = await laptop.service.rotateSecretKey!({ password: PASSWORD, newRecoveryCode: false });
    expect(kit.secretKey).not.toBe(laptop.secretKey);
    expect(kit.recoveryCode).toBeUndefined();
    expect(await laptop.service.getSecretKey()).toBe(kit.secretKey);
    expect((await laptop.service.getSecurityLog()).map((e) => e.type)).toContain('secret-key-rotated');

    // This device unlocks and confirms with the same password, through the new key.
    laptop.service.lock();
    await laptop.service.unlock(PASSWORD);
    expect((await laptop.service.listItems()).map((i) => i.title)).toEqual(['Kept']);

    // The phone remembers the old key: it fails, and the typed new one replaces it.
    phone.service.lock();
    await expectCode(phone.service.signIn({ serverUrl: server.url, email: laptop.email, password: PASSWORD }), 'invalidCredentials');
    expect(await phone.service.signIn({ serverUrl: server.url, email: laptop.email, password: PASSWORD, secretKey: kit.secretKey })).toEqual({ status: 'signedIn' });
    expect((await phone.service.listItems()).map((i) => i.title)).toEqual(['Kept']);
    expect(await phone.service.getSecretKey()).toBe(kit.secretKey);
  });

  it('replaces the recovery code too when asked', async () => {
    const laptop = await signedUp(server.url);
    const kit = await laptop.service.rotateSecretKey!({ password: PASSWORD, newRecoveryCode: true });
    expect(kit.recoveryCode).toBeTruthy();
  });
});

