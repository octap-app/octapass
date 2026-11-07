// Sharing, families, share links, emergency access, devices, live sync and batch imports: the real
// service on two (or three) accounts against the real server. `pnpm --filter @octapass/vault-client test:server`.

import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import type { ItemDraft, LoginDetails } from '../types';
import { device, eventually, expectCode, PASSWORD, signedUp as signUp, type SignedUpDevice } from './testing/devices';
import { startServer, type TestServer } from './testing/server';

let server: TestServer;

beforeAll(async () => {
  server = await startServer();
});
afterAll(() => server?.stop());
afterEach(({ task }) => {
  if (task.result?.state === 'fail') console.error(server.output().split('\n').filter((line) => !line.includes('dev mode')).join('\n'));
});

const signedUp = (options?: Parameters<typeof signUp>[1]) => signUp(server.url, options);

function login(vaultId: string, title: string, password: string): ItemDraft {
  return {
    vaultId,
    overview: { schemaVersion: 1, title, type: 'login', urls: ['https://example.com'] },
    details: { schemaVersion: 1, username: 'maya', password },
  };
}

function keyIdOf(vaultId: string): string {
  const db = new DatabaseSync(join(server.dataDir, 'octapass.db'), { readOnly: true });
  try {
    return (db.prepare('SELECT key_id FROM vaults WHERE id = ?').get(vaultId) as { key_id: string }).key_id;
  } finally {
    db.close();
  }
}

async function share(owner: SignedUpDevice, name: string, members: [SignedUpDevice, 'read' | 'write' | 'manage'][]) {
  const vault = await owner.service.createVault(name);
  for (const [member, role] of members) {
    const account = await owner.service.lookupAccount(member.email);
    await owner.service.addMember(vault.id, account, role);
  }
  return vault;
}

describe('shared vaults', () => {
  it('shares a named vault both ways, live, with fingerprints that match', async () => {
    const [maya, sam] = await Promise.all([signedUp(), signedUp()]);
    const lookup = await maya.service.lookupAccount(` ${sam.email.toUpperCase()} `);
    expect(lookup).toMatchObject({ email: sam.email, fingerprint: await sam.service.getMyFingerprint() });
    expect(lookup.fingerprint.digits).toMatch(/^\d{4}( \d{4}){5}$/);
    await expectCode(maya.service.lookupAccount('nobody-here@example.com'), 'accountNotFound');

    const vault = await maya.service.createVault('Household');
    expect(vault).toMatchObject({ name: 'Household', type: 'shared', role: 'owner' });
    const item = await maya.service.saveItem(login(vault.id, 'Wi-Fi', 'ochre-lantern'));
    await maya.service.addMember(vault.id, lookup, 'write');

    // Sam never syncs by hand: the membership notice arrives over the WebSocket.
    await eventually(async () => expect(await sam.service.listVaults()).toContainEqual({ id: vault.id, name: 'Household', type: 'shared', role: 'write' }));
    const onSam = await eventually(() => sam.service.getItem(item.id));
    expect((onSam.details as LoginDetails).password).toBe('ochre-lantern');
    // The vault's name record is never an item.
    expect((await sam.service.listItems({ vaultId: vault.id })).map((s) => s.title)).toEqual(['Wi-Fi']);

    await sam.service.saveItem({ ...onSam, details: { ...onSam.details, password: 'quartz-anchor' } as LoginDetails });
    await eventually(async () => expect(((await maya.service.getItem(item.id)).details as LoginDetails).password).toBe('quartz-anchor'));

    const members = await maya.service.listMembers(vault.id);
    expect(members.map((m) => [m.email, m.role, m.isYou, m.verified])).toEqual(
      expect.arrayContaining([
        [maya.email, 'owner', true, true],
        [sam.email, 'write', false, false],
      ]),
    );
    expect(members.find((m) => m.email === maya.email)!.fingerprint).toEqual(await maya.service.getMyFingerprint());
    await maya.service.markVerified(lookup);
    expect((await maya.service.listMembers(vault.id)).find((m) => m.email === sam.email)!.verified).toBe(true);

    await maya.service.renameVault(vault.id, 'Home');
    await eventually(async () => expect((await sam.service.listVaults()).find((v) => v.id === vault.id)!.name).toBe('Home'));
  });

  it('enforces roles, and a role change takes effect for the member', async () => {
    const [maya, sam] = await Promise.all([signedUp(), signedUp()]);
    const vault = await share(maya, 'Team', [[sam, 'read']]);
    await eventually(async () => expect((await sam.service.listVaults()).map((v) => v.id)).toContain(vault.id));
    await expectCode(sam.service.saveItem(login(vault.id, 'Nope', 'pw')), 'readOnlyVault');
    await expectCode(sam.service.addMember(vault.id, await sam.service.lookupAccount(maya.email), 'read'), 'notAllowed');

    await maya.service.changeRole(vault.id, (await sam.service.lookupAccount(sam.email)).accountId, 'write');
    await eventually(async () => expect((await sam.service.listVaults()).find((v) => v.id === vault.id)!.role).toBe('write'));
    await expect(sam.service.saveItem(login(vault.id, 'Now allowed', 'pw'))).resolves.toMatchObject({ vaultId: vault.id });
  });

  it('rotates the key after removing a member: the others keep working, the removed one loses the vault', async () => {
    const [maya, sam, leila] = await Promise.all([signedUp(), signedUp(), signedUp()]);
    const vault = await share(maya, 'Family photos', [
      [sam, 'write'],
      [leila, 'read'],
    ]);
    const item = await maya.service.saveItem(login(vault.id, 'Cloud', 'first'));
    await maya.service.moveItem((await maya.service.saveItem(login((await maya.service.listVaults())[0]!.id, 'Moved in', 'pw'))).id, vault.id);
    await eventually(() => leila.service.getItem(item.id));
    const before = keyIdOf(vault.id);

    const leilaId = (await maya.service.listMembers(vault.id)).find((m) => m.email === leila.email)!.accountId!;
    await maya.service.removeMember(vault.id, leilaId);

    expect(keyIdOf(vault.id)).not.toBe(before);
    await eventually(async () => expect((await leila.service.listVaults()).map((v) => v.id)).not.toContain(vault.id));
    await expectCode(leila.service.getItem(item.id), 'notFound');
    expect((await maya.service.listMembers(vault.id)).map((m) => m.email).sort()).toEqual([maya.email, sam.email].sort());

    // Sam opens the new grant and writes under the new key; Maya reads it.
    await eventually(async () => expect((await sam.service.listItems({ vaultId: vault.id })).map((s) => s.title).sort()).toEqual(['Cloud', 'Moved in']));
    const onSam = await sam.service.getItem(item.id);
    await sam.service.saveItem({ ...onSam, details: { ...onSam.details, password: 'after-rotation' } as LoginDetails });
    await eventually(async () => expect(((await maya.service.getItem(item.id)).details as LoginDetails).password).toBe('after-rotation'));
  });

  it('a member can leave, and a grant that fails verification is never used', async () => {
    const [maya, sam] = await Promise.all([signedUp(), signedUp()]);
    const vault = await share(maya, 'Side project', [[sam, 'write']]);
    await maya.service.saveItem(login(vault.id, 'Secret', 'pw'));
    await eventually(async () => expect(await sam.service.listItems({ vaultId: vault.id })).toHaveLength(1));

    // A server (or anyone in between) that changes the role in Sam's grant breaks its signature.
    const tampering: typeof fetch = async (input, init) => {
      const response = await fetch(input, init);
      if (!String(input).includes('/v1/sync')) return response;
      const body = await response.json();
      for (const v of body.vaults) if (v.id === vault.id) v.role = 'owner';
      return new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } });
    };
    const other = await device(undefined, { fetch: tampering });
    await other.service.signIn({ serverUrl: server.url, email: sam.email, password: PASSWORD, secretKey: sam.secretKey });
    expect((await other.service.listVaults()).find((v) => v.id === vault.id)).toMatchObject({ untrusted: true, role: 'owner' });
    expect(await other.service.listItems({ vaultId: vault.id })).toEqual([]);
    await expectCode(other.service.saveItem(login(vault.id, 'Nope', 'pw')), 'untrustedVault');

    await sam.service.leaveVault(vault.id);
    expect((await sam.service.listVaults()).map((v) => v.id)).not.toContain(vault.id);
    expect((await maya.service.listMembers(vault.id)).map((m) => m.email)).toEqual([maya.email]);
  });

  it('copies and moves items between vaults', async () => {
    const maya = await signedUp();
    const personal = (await maya.service.listVaults())[0]!.id;
    const vault = await maya.service.createVault('Work');
    const item = await maya.service.saveItem(login(personal, 'VPN', 'pw'));
    const copy = await maya.service.copyItem(item.id, vault.id);
    expect(copy).toMatchObject({ vaultId: vault.id, overview: { title: 'VPN' } });
    expect((await maya.service.getItem(item.id)).deletedAt).toBeUndefined();
    const moved = await maya.service.moveItem(item.id, vault.id);
    expect(moved.vaultId).toBe(vault.id);
    expect((await maya.service.getItem(item.id)).deletedAt).toBeDefined();
  });
});

describe('families', () => {
  it('invites, accepts, shares the Family vault, and removes with a key rotation', async () => {
    const [maya, sam] = await Promise.all([signedUp(), signedUp()]);
    await maya.service.createFamily();
    const { family } = await maya.service.getFamily();
    expect(family).toMatchObject({ isOrganiser: true, maxMembers: 6, members: [{ email: maya.email, role: 'organiser', isYou: true }] });
    expect((await maya.service.listVaults()).find((v) => v.id === family!.vaultId)).toMatchObject({ name: 'Family', type: 'family', role: 'owner' });
    await expectCode(maya.service.createFamily(), 'alreadyExists');

    await maya.service.inviteToFamily(await maya.service.lookupAccount(sam.email));
    expect((await maya.service.getFamily()).family!.invites.map((i) => i.email)).toEqual([sam.email]);
    const { invitations } = await sam.service.getFamily();
    expect(invitations).toMatchObject([{ familyId: family!.id, organiserEmail: maya.email }]);
    await sam.service.acceptFamilyInvite(family!.id);

    const item = await maya.service.saveItem(login(family!.vaultId, 'Streaming', 'pw'));
    await eventually(() => sam.service.getItem(item.id));
    expect((await sam.service.getFamily()).family).toMatchObject({ isOrganiser: false, invites: [] });

    const before = keyIdOf(family!.vaultId);
    await maya.service.removeFamilyMember((await maya.service.lookupAccount(sam.email)).accountId);
    expect(keyIdOf(family!.vaultId)).not.toBe(before);
    await eventually(async () => expect((await sam.service.listVaults()).map((v) => v.id)).not.toContain(family!.vaultId));
    expect((await sam.service.getFamily()).family).toBeUndefined();

    await maya.service.deleteFamily();
    expect((await maya.service.getFamily()).family).toBeUndefined();
    expect((await maya.service.listVaults()).map((v) => v.type)).toEqual(['personal']);
  });

  it('re-seals pending invites in the rotation, so they open the new key', async () => {
    const [maya, sam, leila, kai] = await Promise.all([signedUp(), signedUp(), signedUp(), signedUp()]);
    await maya.service.createFamily();
    await maya.service.inviteToFamily(await maya.service.lookupAccount(sam.email));
    const { family } = await maya.service.getFamily();
    await sam.service.acceptFamilyInvite(family!.id);
    for (const invitee of [leila, kai]) await maya.service.inviteToFamily(await maya.service.lookupAccount(invitee.email));
    await maya.service.saveItem(login(family!.vaultId, 'Streaming', 'pw'));

    const before = keyIdOf(family!.vaultId);
    await maya.service.removeFamilyMember((await maya.service.lookupAccount(sam.email)).accountId);
    expect(keyIdOf(family!.vaultId)).not.toBe(before);
    expect((await maya.service.getFamily()).family!.invites.map((i) => i.email).sort()).toEqual([leila.email, kai.email].sort());

    await leila.service.acceptFamilyInvite(family!.id);
    expect((await leila.service.listVaults()).find((v) => v.id === family!.vaultId)).toMatchObject({ type: 'family', role: 'write' });
    expect((await leila.service.listItems({ vaultId: family!.vaultId })).map((s) => s.title)).toEqual(['Streaming']);
    // Writing needs the new key: the server refuses item keys wrapped under the old one.
    await leila.service.saveItem(login(family!.vaultId, 'Router', 'pw'));
  });

  it('declines and cancels invites', async () => {
    const [maya, sam, leila] = await Promise.all([signedUp(), signedUp(), signedUp()]);
    await maya.service.createFamily();
    await maya.service.inviteToFamily(await maya.service.lookupAccount(sam.email));
    await maya.service.inviteToFamily(await maya.service.lookupAccount(leila.email));
    const { family } = await maya.service.getFamily();
    await sam.service.declineFamilyInvite(family!.id);
    await maya.service.cancelFamilyInvite((await maya.service.lookupAccount(leila.email)).accountId);
    expect((await maya.service.getFamily()).family!.invites).toEqual([]);
    expect((await leila.service.getFamily()).invitations).toEqual([]);
  });
});

describe('share links', () => {
  it('opens signed out with the key from the fragment and the passphrase, until the views run out', async () => {
    const maya = await signedUp();
    const first = await maya.service.saveItem(login((await maya.service.listVaults())[0]!.id, 'Door code', 'old-door-code'));
    const item = await maya.service.saveItem({ ...first, details: { ...first.details, password: 'tangerine-anvil-5531' } as LoginDetails });
    expect((item.details as LoginDetails).passwordHistory).toHaveLength(1);
    const link = await maya.service.createShareLink(item.id, { expiresInHours: 24, maxViews: 2, passphrase: 'blue heron' });
    expect(link.key.length).toBeGreaterThan(20);
    expect(Date.parse(link.expiresAt) - Date.now()).toBeGreaterThan(23 * 3_600_000);
    expect(await maya.service.listShareLinks()).toMatchObject([{ id: link.id, itemId: item.id, itemTitle: 'Door code', maxViews: 2, views: 0, passphraseRequired: true }]);

    const stranger = await device();
    expect(stranger.service.getSession().status).toBe('signedOut');
    const envelope = await stranger.service.fetchShareLink(server.url, link.id);
    expect(envelope).toMatchObject({ passphraseRequired: true, viewsLeft: 1 });
    await expectCode(stranger.service.openShareLink(envelope.ciphertext, link.key, 'wrong'), 'wrongPassphrase');
    const shared = await stranger.service.openShareLink(envelope.ciphertext, link.key, 'blue heron');
    expect(shared).toMatchObject({ overview: { title: 'Door code' }, details: { password: 'tangerine-anvil-5531' } });
    expect((shared.details as LoginDetails).passwordHistory).toBeUndefined();

    expect((await stranger.service.fetchShareLink(server.url, link.id)).viewsLeft).toBe(0);
    await expectCode(stranger.service.fetchShareLink(server.url, link.id), 'notFound');
    expect(await maya.service.listShareLinks()).toEqual([]);
  });

  it('revokes a link', async () => {
    const maya = await signedUp();
    const item = await maya.service.saveItem(login((await maya.service.listVaults())[0]!.id, 'Alarm', 'pw'));
    const link = await maya.service.createShareLink(item.id, { expiresInHours: 1, maxViews: 5 });
    const stranger = await device();
    const { ciphertext, passphraseRequired } = await stranger.service.fetchShareLink(server.url, link.id);
    expect(passphraseRequired).toBe(false);
    // A link cut short when it was pasted.
    await expectCode(stranger.service.openShareLink(ciphertext, link.key.slice(0, -4)), 'invalidShareLink');
    await maya.service.revokeShareLink(link.id);
    expect(await maya.service.listShareLinks()).toEqual([]);
    await expectCode(stranger.service.fetchShareLink(server.url, link.id), 'notFound');
  });
});

describe('emergency access', () => {
  it('runs request, deny, request and approve, then opens the grantor’s vault read-only', async () => {
    const [maya, sam] = await Promise.all([signedUp(), signedUp()]);
    const pension = await maya.service.saveItem(login((await maya.service.listVaults())[0]!.id, 'Pension', 'heron-ledger'));
    const statement = new TextEncoder().encode('Pension statement, 2026');
    await maya.service.addAttachment(pension.id, new Blob([statement], { type: 'application/pdf' }), 'statement.pdf');
    const contact = await maya.service.addEmergencyContact({ account: await maya.service.lookupAccount(sam.email), waitDays: 7, accessLevel: 'view', scope: { type: 'account' } });
    expect(contact).toMatchObject({ contactEmail: sam.email, status: 'idle', waitDays: 7 });

    const received = (await sam.service.listEmergencyContacts()).received;
    expect(received).toMatchObject([{ id: contact.id, grantorEmail: maya.email }]);
    await expectCode(sam.service.openEmergencyAccess(contact.id), 'notAllowed');

    await sam.service.requestEmergencyAccess(contact.id);
    const requested = (await maya.service.listEmergencyContacts()).granted[0]!;
    expect(requested.status).toBe('requested');
    expect(Date.parse(requested.releasesAt!) - Date.parse(requested.requestedAt!)).toBe(7 * 86_400_000);
    await maya.service.denyEmergencyAccess(contact.id);
    expect((await sam.service.listEmergencyContacts()).received[0]!.status).toBe('idle');

    await sam.service.requestEmergencyAccess(contact.id);
    await maya.service.approveEmergencyAccess(contact.id);
    const view = await sam.service.openEmergencyAccess(contact.id);
    expect(view.vaults).toEqual([{ id: expect.any(String), name: 'Personal', type: 'personal', role: 'read' }]);
    expect(view.items.map((i) => [i.overview.title, (i.details as LoginDetails).password])).toEqual([['Pension', 'heron-ledger']]);
    // The grantor's files too, decrypted on the contact's device.
    const [file] = view.items[0]!.details.attachments!;
    expect(file).toMatchObject({ name: 'statement.pdf', size: statement.length });
    const downloaded = await sam.service.getEmergencyAttachment(contact.id, pension.id, file!.id);
    expect(downloaded.type).toBe('application/pdf');
    expect(new Uint8Array(await downloaded.arrayBuffer())).toEqual(statement);
    await expectCode(sam.service.getEmergencyAttachment(contact.id, pension.id, crypto.randomUUID()), 'notFound');

    expect((await maya.service.getSecurityLog()).map((e) => e.type)).toEqual([
      'emergency-access-approved',
      'emergency-access-requested',
      'emergency-access-denied',
      'emergency-access-requested',
      'emergency-contact-added',
    ]);
    await sam.service.removeEmergencyContact(contact.id);
    expect((await maya.service.listEmergencyContacts()).granted).toEqual([]);
    await expectCode(sam.service.getEmergencyAttachment(contact.id, pension.id, file!.id), 'notFound');
  });

  it('shares a single vault with a contact', async () => {
    const [maya, sam] = await Promise.all([signedUp(), signedUp()]);
    const vault = await maya.service.createVault('Documents');
    const will = await maya.service.saveItem(login(vault.id, 'Will', 'notary'));
    const willFile = await maya.service.addAttachment(will.id, new Blob(['signed copy'], { type: 'text/plain' }), 'will.txt');
    const diary = await maya.service.saveItem(login((await maya.service.listVaults())[0]!.id, 'Diary', 'private'));
    const diaryFile = await maya.service.addAttachment(diary.id, new Blob(['dear diary'], { type: 'text/plain' }), 'diary.txt');
    const contact = await maya.service.addEmergencyContact({
      account: await maya.service.lookupAccount(sam.email),
      waitDays: 1,
      accessLevel: 'view',
      scope: { type: 'vault', vaultId: vault.id },
    });
    await sam.service.requestEmergencyAccess(contact.id);
    await maya.service.approveEmergencyAccess(contact.id);
    const view = await sam.service.openEmergencyAccess(contact.id);
    expect(view.vaults).toEqual([{ id: vault.id, name: 'Documents', type: 'shared', role: 'read' }]);
    expect(view.items.map((i) => i.overview.title)).toEqual(['Will']);
    expect(await (await sam.service.getEmergencyAttachment(contact.id, will.id, willFile.details.attachments![0]!.id)).text()).toBe('signed copy');
    // Outside the vault in scope, the grantor's files don't exist for the contact.
    await expectCode(sam.service.getEmergencyAttachment(contact.id, diary.id, diaryFile.details.attachments![0]!.id), 'notFound');
  });
});

describe('key rotation and takeover', () => {
  const NEW_PASSWORD = 'Copper meadow lantern swift 77';

  it('rotates a personal vault on demand, and a device on the old key catches up', async () => {
    const laptop = await signedUp();
    const phone = await device();
    await phone.service.signIn({ serverUrl: server.url, email: laptop.email, password: PASSWORD, secretKey: laptop.secretKey });
    const [vault] = await laptop.service.listVaults();
    const before = await laptop.service.saveItem(login(vault!.id, 'Bank', 'ochre-lantern'));
    await eventually(async () => expect((await phone.service.listItems()).length).toBe(1));

    await laptop.service.sharing!.rotateVaultKey(vault!.id);
    expect((await laptop.service.getItem(before.id)).overview.title).toBe('Bank');
    expect((await laptop.service.sharing!.getSecurityLog()).map((e) => e.type)).toContain('vault-key-rotated');

    // The phone hasn't synced, so its first attempt is refused, and it sends again on the new key.
    const fromPhone = await phone.service.saveItem(login(vault!.id, 'From the phone', 'moss-river'));
    await eventually(async () => expect((await laptop.service.listItems()).map((i) => i.id)).toContain(fromPhone.id));
    expect((await laptop.service.getItem(fromPhone.id)).details).toMatchObject({ password: 'moss-river' });
  });

  it('takes a vault-scoped contact off a rotated vault until the grantor renews them', async () => {
    const [grace, carl] = await Promise.all([signedUp(), signedUp()]);
    const vault = (await grace.service.listVaults())[0]!;
    await grace.service.saveItem(login(vault.id, 'Pension', 'moss-river'));
    const account = await grace.service.lookupAccount(carl.email);
    const contact = await grace.service.sharing!.addEmergencyContact({ account, waitDays: 1, accessLevel: 'view', scope: { type: 'vault', vaultId: vault.id } });

    await grace.service.sharing!.rotateVaultKey(vault.id);
    expect((await grace.service.sharing!.listEmergencyContacts()).granted[0]!.keyStale).toBe(true);
    await grace.service.sharing!.renewEmergencyKey(contact.id, account);
    expect((await grace.service.sharing!.listEmergencyContacts()).granted[0]!.keyStale).toBeFalsy();

    await carl.service.sharing!.requestEmergencyAccess(contact.id);
    await grace.service.sharing!.approveEmergencyAccess(contact.id);
    const view = await carl.service.sharing!.openEmergencyAccess(contact.id);
    expect(view.items.map((i) => i.overview.title)).toEqual(['Pension']);
  });

  it('runs a takeover: the kit opens the account, the grantor is out, the record is gone', async () => {
    const [grace, carl] = await Promise.all([signedUp(), signedUp()]);
    const vault = (await grace.service.listVaults())[0]!;
    await grace.service.saveItem(login(vault.id, 'Pension', 'moss-river'));
    const account = await grace.service.lookupAccount(carl.email);
    const contact = await grace.service.sharing!.addEmergencyContact({ account, waitDays: 1, accessLevel: 'takeover', scope: { type: 'account' } });

    await expectCode(carl.service.sharing!.takeOverAccount(contact.id, { contactPassword: PASSWORD, newPassword: NEW_PASSWORD }), 'notAllowed');
    await carl.service.sharing!.requestEmergencyAccess(contact.id);
    await grace.service.sharing!.approveEmergencyAccess(contact.id);
    await expectCode(carl.service.sharing!.takeOverAccount(contact.id, { contactPassword: 'wrong password', newPassword: NEW_PASSWORD }), 'invalidCredentials');
    const kit = await carl.service.sharing!.takeOverAccount(contact.id, { contactPassword: PASSWORD, newPassword: NEW_PASSWORD });
    expect(kit).toMatchObject({ email: grace.email, serverUrl: server.url });
    expect(kit.secretKey).not.toBe(grace.secretKey);
    expect(kit.recoveryCode).toBeTruthy();
    expect((await carl.service.sharing!.listEmergencyContacts()).received).toEqual([]);

    const fresh = await device();
    await fresh.service.signIn({ serverUrl: server.url, email: grace.email, password: NEW_PASSWORD, secretKey: kit.secretKey });
    expect((await fresh.service.listItems()).map((i) => i.title)).toEqual(['Pension']);
    expect((await fresh.service.sharing!.getSecurityLog()).map((e) => e.type)).toContain('emergency-takeover');
    const stale = await device();
    await expectCode(stale.service.signIn({ serverUrl: server.url, email: grace.email, password: PASSWORD, secretKey: grace.secretKey }), 'invalidCredentials');
  });

  it('lets a family member opt in to organiser recovery, which allows the reset and no reading', async () => {
    const [olive, sam] = await Promise.all([signedUp(), signedUp()]);
    await olive.service.sharing!.createFamily();
    await olive.service.sharing!.inviteToFamily(await olive.service.lookupAccount(sam.email));
    const { invitations } = await sam.service.sharing!.getFamily();
    await sam.service.sharing!.acceptFamilyInvite(invitations[0]!.familyId);

    const organiser = await sam.service.lookupAccount(olive.email);
    const record = await sam.service.sharing!.enableOrganiserRecovery({ account: organiser, waitDays: 1 });
    expect(record).toMatchObject({ organiserRecovery: true, accessLevel: 'takeover', scope: { type: 'account' } });
    await olive.service.sharing!.requestEmergencyAccess(record.id);
    await sam.service.sharing!.approveEmergencyAccess(record.id);
    await expectCode(olive.service.sharing!.openEmergencyAccess(record.id), 'notAllowed');
    const kit = await olive.service.sharing!.takeOverAccount(record.id, { contactPassword: PASSWORD, newPassword: NEW_PASSWORD });
    expect(kit.email).toBe(sam.email);
  });
});

describe('devices and live sync', () => {
  it('lists, renames and remotely signs out devices; the signed-out one is told at once', async () => {
    const maya = await signedUp();
    const laptop = await device();
    await laptop.service.signIn({ serverUrl: server.url, email: maya.email, password: PASSWORD, secretKey: maya.secretKey });

    const devices = await maya.service.listDevices();
    expect(devices).toHaveLength(2);
    expect(devices.filter((d) => d.current)).toHaveLength(1);
    expect((await maya.service.getAccountSummary()).deviceCount).toBe(2);
    await maya.service.renameDevice('Kitchen iPad');
    expect((await maya.service.listDevices()).find((d) => d.current)!.name).toBe('Kitchen iPad');

    const other = devices.find((d) => !d.current)!;
    await maya.service.signOutDevice(other.id);
    await eventually(() => expect(laptop.service.getSession().status).toBe('signedOut'));
    // Like an expired session: the Secret Key stays, so signing in again here needs only the password.
    expect(laptop.service.rememberedAccounts()).toEqual([{ email: maya.email, serverUrl: server.url }]);
    expect(await maya.service.listDevices()).toHaveLength(1);
  });

  it('brings another device’s edits in over the WebSocket, and reports what it owns alone', async () => {
    const maya = await signedUp();
    const tablet = await device();
    await tablet.service.signIn({ serverUrl: server.url, email: maya.email, password: PASSWORD, secretKey: maya.secretKey });
    const changed = new Promise<void>((resolve) => tablet.service.onItemsChange(resolve));
    const item = await maya.service.saveItem(login((await maya.service.listVaults())[0]!.id, 'Live', 'pw'));
    await changed;
    await eventually(() => tablet.service.getItem(item.id));

    await maya.service.createVault('Solo');
    expect((await maya.service.getAccountSummary()).sharedVaultsOwned).toEqual(['Solo']);
  });
});

describe('batch import', () => {
  it('imports 1,500 rows in two batch requests', async () => {
    let batches = 0;
    const counting: typeof fetch = (input, init) => {
      if (String(input).endsWith('/v1/batch')) batches++;
      return fetch(input, init);
    };
    const maya = await signedUp({ fetch: counting });
    const rows = Array.from({ length: 1500 }, (_, i) => `Site ${i},https://site${i}.example,user${i},pw-${i},`);
    const result = await maya.service.importFile('chrome', new File([`name,url,username,password,note\n${rows.join('\n')}\n`], 'passwords.csv'));
    expect(result).toEqual({ imported: 1500, skipped: 0, warnings: [] });
    expect(batches).toBe(2);
    expect(await maya.service.listItems()).toHaveLength(1500);
    const reloaded = await device(maya.storage);
    await reloaded.service.unlock(PASSWORD);
    expect(await reloaded.service.listItems()).toHaveLength(1500);
  });
});
