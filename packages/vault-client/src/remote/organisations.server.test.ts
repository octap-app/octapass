// Organisations end to end: the real service on real accounts against the real server, with real
// sealed grants. `pnpm --filter @octapass/vault-client test:server`.

import { signedUp as signUp, eventually, expectCode, PASSWORD, type SignedUpDevice } from './testing/devices';
import { startServer, type TestServer } from './testing/server';
import type { ItemDraft } from '../types';

let server: TestServer;

beforeAll(async () => {
  server = await startServer();
});
afterAll(() => server?.stop());

const signedUp = () => signUp(server.url);

function login(vaultId: string, title: string): ItemDraft {
  return {
    vaultId,
    overview: { schemaVersion: 1, title, type: 'login', urls: ['https://example.com'] },
    details: { schemaVersion: 1, username: 'maya', password: 'ochre-lantern' },
  };
}

async function join(admin: SignedUpDevice, person: SignedUpDevice) {
  await admin.service.inviteOrgMember(person.email, 'member');
  const { invitations } = await person.service.getOrganisation();
  await person.service.acceptOrgInvite(invitations[0]!.orgId, invitations[0]!.id);
  const { members } = await admin.service.listOrgMembers();
  return members.find((member) => member.email === person.email)!;
}

async function orgWithVault() {
  const [owner, member] = await Promise.all([signedUp(), signedUp()]);
  await owner.service.createOrganisation('Acme');
  const joined = await join(owner, member);
  await owner.service.createOrgVault('Finance');
  const [vault] = await owner.service.listOrgVaults();
  const group = await owner.service.createOrgGroup('Accounts');
  await owner.service.linkOrgVaultGroup(vault!.id, group.id, 'write');
  await owner.service.addOrgGroupMember(group.id, joined.accountId);
  return { owner, member, accountId: joined.accountId, vaultId: vault!.id, groupId: group.id };
}

describe('organisations', { timeout: 60_000 }, () => {
  it('reaches a member only through a grant sealed after review, and the vault then opens', async () => {
    const { owner, member, vaultId } = await orgWithVault();
    await owner.service.saveItem(login(vaultId, 'Bank'));

    // In a group, but holding nothing.
    await member.engine.call('sync', []);
    expect((await member.service.listVaults()).some((vault) => vault.id === vaultId)).toBe(false);

    const [review] = await owner.service.getOrgAccess();
    expect(review).toMatchObject({ vaultId, vaultName: 'Finance', canApply: true });
    const grant = review!.grants[0]!;
    expect(grant).toMatchObject({ email: member.email, role: 'write', keyChanged: false });
    // The fingerprint comes from this device, over the keys the server sent.
    expect(grant.fingerprint).toEqual(await member.service.getMyFingerprint());

    await owner.service.applyOrgAccess(vaultId, [grant]);
    await member.engine.call('sync', []);
    const vault = (await member.service.listVaults()).find((v) => v.id === vaultId);
    expect(vault).toMatchObject({ name: 'Finance', type: 'shared', role: 'write' });
    const items = await member.service.listItems({ vaultId });
    expect(items.map((item) => item.title)).toContain('Bank');
    expect(await owner.service.getOrgAccess()).toEqual([]);
  });

  it('refuses to seal when the keys aren’t the ones that were reviewed', async () => {
    const { owner, vaultId } = await orgWithVault();
    const [review] = await owner.service.getOrgAccess();
    const grant = review!.grants[0]!;
    const swapped = { ...grant, fingerprint: { ...grant.fingerprint, digits: '0000 0000 0000 0000 0000 0000' } };
    await expectCode(owner.service.applyOrgAccess(vaultId, [swapped]), 'untrustedVault');
    expect(await owner.service.getOrgAccess()).toHaveLength(1);
  });

  it('seals to nobody who wasn’t on screen', async () => {
    const { owner, vaultId, groupId } = await orgWithVault();
    const [review] = await owner.service.getOrgAccess();
    const third = await signedUp();
    const joined = await join(owner, third);
    await owner.service.addOrgGroupMember(groupId, joined.accountId);

    await owner.service.applyOrgAccess(vaultId, review!.grants);
    await third.engine.call('sync', []);
    expect((await third.service.listVaults()).some((vault) => vault.id === vaultId)).toBe(false);
    const [next] = await owner.service.getOrgAccess();
    expect(next!.grants.map((grant) => grant.email)).toEqual([third.email]);
  });

  it('takes access away at once, then rotates the key', async () => {
    const { owner, member, accountId, vaultId, groupId } = await orgWithVault();
    const [review] = await owner.service.getOrgAccess();
    await owner.service.applyOrgAccess(vaultId, review!.grants);
    await member.engine.call('sync', []);
    expect((await member.service.listVaults()).some((vault) => vault.id === vaultId)).toBe(true);

    await owner.service.removeOrgGroupMember(groupId, accountId);
    await eventually(async () => {
      await member.engine.call('sync', []);
      expect((await member.service.listVaults()).some((vault) => vault.id === vaultId)).toBe(false);
    });
    const [due] = await owner.service.getOrgAccess();
    expect(due).toMatchObject({ vaultId, rotate: true });
    await owner.service.rotateOrgVault(vaultId);
    expect(await owner.service.getOrgAccess()).toEqual([]);
    await owner.service.saveItem(login(vaultId, 'After rotation'));
    expect((await owner.service.listItems({ vaultId })).map((item) => item.title)).toContain('After rotation');
  });

  it('applies the export policy on this device', async () => {
    const { owner, vaultId } = await orgWithVault();
    await owner.service.saveItem(login(vaultId, 'Organisation secret'));
    const before = await (await owner.service.exportVault('json', { masterPassword: PASSWORD })).text();
    expect(before).toContain('Organisation secret');

    const { organisation } = await owner.service.getOrganisation();
    await owner.service.setOrgPolicies({ ...organisation!.policies, disableExport: true });
    const after = await (await owner.service.exportVault('json', { masterPassword: PASSWORD })).text();
    expect(after).not.toContain('Organisation secret');
  });

  it('refuses a share link under the policy', async () => {
    const { owner, member } = await orgWithVault();
    const { organisation } = await owner.service.getOrganisation();
    await owner.service.setOrgPolicies({ ...organisation!.policies, disableShareLinks: true });
    const item = await member.service.saveItem(login((await member.service.listVaults())[0]!.id, 'Mine'));
    await expectCode(member.service.createShareLink(item.id, { expiresInHours: 1, maxViews: 1 }), 'orgPolicy');
  });

  it('deletes with the master password, and only the organisation’s vaults', async () => {
    const { owner, vaultId } = await orgWithVault();
    await expectCode(owner.service.deleteOrganisation({ password: 'wrong password here', confirmName: 'Acme' }), 'invalidCredentials');
    await owner.service.deleteOrganisation({ password: PASSWORD, confirmName: 'Acme' });
    const vaults = await owner.service.listVaults();
    expect(vaults.some((vault) => vault.id === vaultId)).toBe(false);
    expect(vaults.some((vault) => vault.type === 'personal')).toBe(true);
    expect((await owner.service.getOrganisation()).organisation).toBeUndefined();
  });

  it('saves SAML settings and makes SCIM tokens a provider can use', async () => {
    const owner = await signedUp();
    await owner.service.createOrganisation('Acme');
    const sso = await owner.service.getOrgSso();
    expect(sso.protocol).toBeUndefined();
    expect(sso.samlServiceProvider.acsUrl).toMatch(/\/v1\/sso\/saml\/.+\/acs$/);
    await expectCode(owner.service.saveOrgSaml({ entityId: 'https://idp.example.com', ssoUrl: 'https://idp.example.com/sso', certificates: ['not a certificate'] }), 'ssoConfig');

    const { token, secret } = await owner.service.createOrgScimToken('Okta');
    expect(secret).toMatch(/^opscim_/);
    const scim = await owner.service.getOrgScim();
    expect(scim.tokens.map((listed) => listed.id)).toEqual([token.id]);
    const users = await fetch(`${scim.baseUrl}/Users`, { headers: { authorization: `Bearer ${secret}` } });
    expect(users.status).toBe(200);
    expect(await users.json()).toMatchObject({ totalResults: 0 });
    await owner.service.revokeOrgScimToken(token.id);
    const revoked = await fetch(`${scim.baseUrl}/Users`, { headers: { authorization: `Bearer ${secret}` } });
    expect(revoked.status).toBe(401);
  });
});
