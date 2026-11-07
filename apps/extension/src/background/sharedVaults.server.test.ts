// Shared and family vaults in the extension, against the real octapass-server: the owner shares
// from the web vault (the same service), and the extension's member lists, fills and uses passkeys
// from them, through a key rotation and a removal. Run with
// `pnpm --filter @octapass/extension test:server`.

import type { LoginDetails, Vault } from '@octapass/vault-client';
import type { Core } from '@octapass/vault-client/remote';
import { device, eventually, signedUp as signedUpWeb, type SignedUpDevice } from '@octapass/vault-client/remote/testing/devices';
import { startServer, type TestServer } from '@octapass/vault-client/remote/testing/server';
import { testCore } from '../test/core';
import { memoryStore } from '../test/memoryStore';
import { withAccountSession, type AccountCache } from './accountSession';
import { Matcher } from './matching';
import { PasskeyAuthenticator } from './passkeys';
import { openKeyValueStore } from './storage';
import { VaultHost } from './vault';

const core = testCore as unknown as Core;
const matcher = new Matcher(testCore);
const PASSWORD = 'Lantern ruby quiet anchor 42';
const b64 = (bytes: Uint8Array | string) => Buffer.from(bytes).toString('base64url');

let server: TestServer;
beforeAll(async () => {
  server = await startServer();
});
afterAll(() => server?.stop());

let profiles = 0;
let emails = 0;

/** The extension, signed up as a new account. */
async function extension() {
  const profile = { disk: await openKeyValueStore(`shared-profile-${profiles++}`), memory: memoryStore() };
  const host = await VaultHost.start({ loadCore: async () => testCore, ...profile, device: { name: 'Test extension', platform: 'extension' } });
  const email = `member${emails++}-${Date.now()}@example.com`;
  const { signupId, devVerificationCode } = (await host.pageCall('startSignup', [{ serverUrl: server.url, email, password: PASSWORD }])) as { signupId: string; devVerificationCode: string };
  await host.pageCall('finishSignup', [{ signupId, verificationCode: devVerificationCode }]);
  await eventually(async () => expect(await host.keeper.read()).toBeTruthy());
  const authenticator = new PasskeyAuthenticator({ host, matcher, keeper: host.keeper, loadCore: async () => core, disk: profile.disk });
  return { host, profile, email, authenticator };
}

function login(vaultId: string, title: string, password: string) {
  return { vaultId, overview: { schemaVersion: 1 as const, title, type: 'login' as const, urls: ['https://login.example.com'] }, details: { schemaVersion: 1 as const, username: 'maya@example.com', password } };
}

const titles = async (host: VaultHost, vaultId: string) =>
  (await host.listItems())
    .filter((i) => i.vaultId === vaultId && !i.deletedAt)
    .map((i) => i.title)
    .sort();

async function share(owner: SignedUpDevice, vaultId: string, email: string, role: 'read' | 'write') {
  await owner.service.addMember(vaultId, await owner.service.lookupAccount(email), role);
}

describe('shared vaults in the extension', () => {
  it('lists, fills and makes passkeys from shared and family vaults, through a rotation', async () => {
    const [maya, sam] = await Promise.all([signedUpWeb(server.url), signedUpWeb(server.url)]);
    const member = await extension();

    const team = await maya.service.createVault('Team');
    const router = await maya.service.saveItem(login(team.id, 'Router', 'ochre-lantern'));
    await share(maya, team.id, member.email, 'write');
    await share(maya, team.id, sam.email, 'read');
    await maya.service.createFamily();
    await maya.service.inviteToFamily(await maya.service.lookupAccount(member.email));
    const family = (await maya.service.listVaults()).find((v) => v.type === 'family')!;
    await maya.service.saveItem(login(family.id, 'Streaming', 'quartz'));

    await member.host.pageCall('sync', []);
    const vaults = (await member.host.pageCall('listVaults', [])) as Vault[];
    expect(vaults.find((v) => v.id === team.id)).toEqual({ id: team.id, name: 'Team', type: 'shared', role: 'write' });
    expect(await titles(member.host, team.id)).toEqual(['Router']);
    expect(((await member.host.getItem(router.id)).details as LoginDetails).password).toBe('ochre-lantern');
    // Autofill offers the shared login on its site.
    const offered = matcher.logins(await member.host.listItems(), 'https://login.example.com');
    expect(offered.map((s) => s.title)).toContain('Router');

    // A passkey for that site goes into the shared login (same account name, writable vault),
    // and signs in from there.
    const caller = { origin: 'https://login.example.com' };
    await member.authenticator.create(
      {
        rp: { id: 'login.example.com', name: 'Example' },
        user: { id: b64('user-1'), name: 'maya@example.com', displayName: 'Maya' },
        challenge: b64(new Uint8Array(32).fill(1)),
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      },
      caller,
    );
    await eventually(async () => expect((await member.host.listItems()).find((i) => i.id === router.id)?.hasPasskey).toBe(true));
    const request = { challenge: b64(new Uint8Array(32).fill(2)), rpId: 'login.example.com' };
    const [match] = await member.authenticator.find(request, caller);
    expect(match).toMatchObject({ itemId: router.id });
    await expect(member.authenticator.assert(request, caller, match!)).resolves.toMatchObject({ type: 'public-key' });
    await eventually(async () => expect((await maya.service.getItem(router.id)).details).toHaveProperty('passkeys'));

    // The family vault, once the invite is accepted (from the web vault: the extension has no
    // sharing screens).
    const memberWeb = await signedInWeb(member.email, (await member.host.pageCall('getSecretKey', [])) as string);
    const { invitations: pending } = await memberWeb.service.getFamily();
    await memberWeb.service.acceptFamilyInvite(pending[0]!.familyId);
    await member.host.pageCall('sync', []);
    expect(await titles(member.host, family.id)).toEqual(['Streaming']);

    // Sam is removed and the key rotated: the extension keeps reading and writing.
    const samId = (await maya.service.listMembers(team.id)).find((m) => m.email === sam.email)!.accountId!;
    await maya.service.removeMember(team.id, samId);
    await member.host.pageCall('sync', []);
    expect(await titles(member.host, team.id)).toEqual(['Router']);
    await member.host.pageCall('saveItem', [login(team.id, 'Printer', 'pw')]);
    await eventually(async () => expect((await maya.service.listItems({ vaultId: team.id })).map((s) => s.title).sort()).toEqual(['Printer', 'Router']));
    await expect(member.authenticator.find(request, caller)).resolves.toHaveLength(1);
  });

  it('can’t write to a read-only vault, and loses a vault it was removed from', async () => {
    const maya = await signedUpWeb(server.url);
    const member = await extension();
    const team = await maya.service.createVault('Read only');
    await maya.service.saveItem(login(team.id, 'Router', 'pw'));
    await share(maya, team.id, member.email, 'read');
    await member.host.pageCall('sync', []);
    expect(await titles(member.host, team.id)).toEqual(['Router']);
    await expect(member.host.pageCall('saveItem', [login(team.id, 'Mine', 'pw')])).rejects.toMatchObject({ code: 'readOnlyVault' });

    // A new passkey for the site goes to the personal vault, not the read-only login.
    const caller = { origin: 'https://login.example.com' };
    await member.authenticator.create(
      {
        rp: { id: 'login.example.com', name: 'Example' },
        user: { id: b64('user-2'), name: 'maya@example.com', displayName: 'Maya' },
        challenge: b64(new Uint8Array(32).fill(3)),
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      },
      caller,
    );
    const personal = ((await member.host.pageCall('listVaults', [])) as Vault[]).find((v) => v.type === 'personal')!;
    await eventually(async () => expect((await member.host.listItems()).filter((i) => i.hasPasskey).map((i) => i.vaultId)).toEqual([personal.id]));

    const memberId = (await maya.service.listMembers(team.id)).find((m) => m.email === member.email)!.accountId!;
    await maya.service.removeMember(team.id, memberId);
    await member.host.pageCall('sync', []);
    expect(((await member.host.pageCall('listVaults', [])) as Vault[]).map((v) => v.id)).not.toContain(team.id);
    expect(await titles(member.host, team.id)).toEqual([]);
  });

  it('keeps a vault whose grant doesn’t verify closed, and passkeys still work', async () => {
    const maya = await signedUpWeb(server.url);
    const member = await extension();
    const team = await maya.service.createVault('Team');
    await share(maya, team.id, member.email, 'read');
    await member.host.pageCall('sync', []);
    await eventually(async () => expect(((await member.host.pageCall('listVaults', [])) as Vault[]).map((v) => v.id)).toContain(team.id));

    // The cached grant no longer matches what was signed (a server that changed the role).
    const { accountId } = (await member.profile.disk.get<{ accountId: string }>('session'))!;
    const cache = (await member.profile.disk.get<AccountCache>(`vault-cache:${accountId}`))!;
    const tampered = { ...cache, vaults: cache.vaults.map((v) => (v.id === team.id ? { ...v, role: 'write' as const } : v)) };
    await member.profile.disk.set(`vault-cache:${accountId}`, tampered);
    const options = { keeper: member.host.keeper, loadCore: async () => core, disk: member.profile.disk };
    const untrusted = await withAccountSession(options, async ({ untrusted, session }) => {
      expect(session.isVaultOpen(team.id)).toBe(false);
      return [...untrusted];
    });
    expect(untrusted).toEqual([team.id]);
    await member.profile.disk.set(`vault-cache:${accountId}`, cache);
    const request = { challenge: b64(new Uint8Array(32)), rpId: 'login.example.com' };
    await expect(member.authenticator.find(request, { origin: 'https://login.example.com' })).resolves.toEqual([]);
  });
});

/** The same account in the web vault, for what the extension has no screens for. */
async function signedInWeb(email: string, secretKey: string): Promise<SignedUpDevice> {
  const web = await device();
  await web.service.signIn({ serverUrl: server.url, email, password: PASSWORD, secretKey });
  return { ...web, email, secretKey };
}
