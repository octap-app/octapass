import { isVaultError } from '../errors';
import { attachmentsOf } from '../items';
import type { LoginDetails } from '../types';
import { DEFAULT_SERVER_URL, MockVaultService } from './MockVaultService';

let db = 0;
const password = 'Lantern ruby quiet anchor';

async function signedUp(options: { seed?: boolean; dbName?: string } = {}) {
  const service = await MockVaultService.create({ dbName: options.dbName ?? `sharing-${db++}`, latency: [0, 0], fetch: async () => new Response(''), seed: options.seed ?? true });
  const { signupId, devVerificationCode } = await service.startSignup({ serverUrl: DEFAULT_SERVER_URL, email: 'maya@example.com', password });
  await service.finishSignup({ signupId, verificationCode: devVerificationCode! });
  return service;
}

async function expectCode(promise: Promise<unknown>, code: Parameters<typeof isVaultError>[1]) {
  const error = await promise.then(() => undefined, (e: unknown) => e);
  expect(isVaultError(error, code)).toBe(true);
}

describe('MockSharing', () => {
  it('is the service’s sharing capability', async () => {
    const service = await signedUp();
    expect(service.sharing).toBeDefined();
    expect(await service.sharing.listDevices()).toHaveLength(3);
    expect((await service.getAccountSummary()).deviceCount).toBe(3);
  });

  it('looks people up with stable fingerprints, and remembers which were verified', async () => {
    const { sharing } = await signedUp();
    const sam = await sharing.lookupAccount(' Sam@Example.com ');
    expect(sam.email).toBe('sam@example.com');
    expect(sam.fingerprint.digits).toMatch(/^\d{4}( \d{4}){5}$/);
    expect(sam.fingerprint.emoji).toHaveLength(8);
    expect((await sharing.lookupAccount('sam@example.com')).fingerprint).toEqual(sam.fingerprint);
    await expectCode(sharing.lookupAccount('ghost@nowhere.invalid'), 'accountNotFound');

    const vault = await sharing.createVault('Trip');
    await sharing.addMember(vault.id, sam, 'write');
    expect((await sharing.listMembers(vault.id)).find((m) => m.email === sam.email)?.verified).toBe(false);
    await sharing.markVerified(sam);
    expect((await sharing.listMembers(vault.id)).find((m) => m.email === sam.email)?.verified).toBe(true);
  });

  it('creates, renames and manages a shared vault by role', async () => {
    const service = await signedUp();
    const { sharing } = service;
    const changes = vi.fn();
    sharing.onSharingChange(changes);
    const vault = await sharing.createVault('  Trip  ');
    expect(vault).toMatchObject({ name: 'Trip', type: 'shared', role: 'owner' });
    await sharing.renameVault(vault.id, 'Lisbon trip');
    expect((await service.listVaults()).find((v) => v.id === vault.id)?.name).toBe('Lisbon trip');

    const priya = await sharing.lookupAccount('priya@example.com');
    await sharing.addMember(vault.id, priya, 'read');
    await sharing.changeRole(vault.id, priya.accountId, 'manage');
    expect((await sharing.listMembers(vault.id)).map((m) => [m.email, m.role, m.isYou])).toEqual([
      ['maya@example.com', 'owner', true],
      ['priya@example.com', 'manage', false],
    ]);
    await sharing.removeMember(vault.id, priya.accountId);
    expect(await sharing.listMembers(vault.id)).toHaveLength(1);
    expect(changes).toHaveBeenCalled();

    // The last owner can't leave; a manager can't hand out owner.
    await expectCode(sharing.leaveVault(vault.id), 'notAllowed');
    const studio = (await service.listVaults()).find((v) => v.name === 'Studio')!;
    expect(studio.role).toBe('manage');
    await expectCode(sharing.addMember(studio.id, priya, 'owner'), 'notAllowed');
    await sharing.leaveVault(studio.id);
    expect((await service.listVaults()).map((v) => v.name)).not.toContain('Studio');
  });

  it('copies and moves items between vaults', async () => {
    const service = await signedUp();
    const [personal, family] = await service.listVaults();
    const github = (await service.listItems({ vaultId: personal!.id })).find((s) => s.title === 'GitHub')!;
    const copy = await service.sharing.copyItem(github.id, family!.id);
    expect(copy).toMatchObject({ vaultId: family!.id, overview: { title: 'GitHub', favorite: false } });
    expect(((await service.getItem(copy.id)).details as LoginDetails).totp).toBeDefined();
    const moved = await service.sharing.moveItem(github.id, family!.id);
    expect((await service.getItem(github.id)).deletedAt).toBeDefined();
    expect(moved.vaultId).toBe(family!.id);
  });

  it('runs a family: invites up to six, removes, leaves and deletes', async () => {
    const service = await signedUp({ seed: false });
    const { sharing } = service;
    expect(await sharing.getFamily()).toEqual({ invitations: [] });
    await sharing.createFamily();
    await expectCode(sharing.createFamily(), 'alreadyExists');
    const { family } = await sharing.getFamily();
    expect(family).toMatchObject({ isOrganiser: true, maxMembers: 6, members: [{ email: 'maya@example.com', role: 'organiser', isYou: true }] });
    expect((await service.listVaults()).find((v) => v.id === family!.vaultId)).toMatchObject({ name: 'Family', type: 'family' });

    for (const name of ['a', 'b', 'c', 'd', 'e']) await sharing.inviteToFamily(await sharing.lookupAccount(`${name}@example.com`));
    await expectCode(sharing.inviteToFamily(await sharing.lookupAccount('f@example.com')), 'familyFull');
    const invites = (await sharing.getFamily()).family!.invites;
    expect(invites).toHaveLength(5);
    await sharing.cancelFamilyInvite(invites[0]!.accountId);
    expect((await sharing.getFamily()).family!.invites).toHaveLength(4);

    await expectCode(sharing.leaveFamily(), 'notAllowed');
    await sharing.deleteFamily();
    expect((await sharing.getFamily()).family).toBeUndefined();
    expect((await service.listVaults()).map((v) => v.type)).toEqual(['personal']);
  });

  it('removes a seeded family member from the family and its vault', async () => {
    const service = await signedUp();
    const { family } = await service.sharing.getFamily();
    const sam = family!.members.find((m) => m.email === 'sam.rahman@example.com')!;
    await service.sharing.removeFamilyMember(sam.accountId);
    expect((await service.sharing.getFamily()).family!.members.map((m) => m.email)).not.toContain(sam.email);
    expect((await service.sharing.listMembers(family!.vaultId)).map((m) => m.email)).not.toContain(sam.email);
  });

  it('makes share links that open signed out, count views and need the passphrase', async () => {
    const dbName = `sharing-${db++}`;
    const service = await signedUp({ dbName });
    const item = (await service.listItems()).find((s) => s.title === 'GitHub')!;
    await expectCode(service.sharing.createShareLink(item.id, { expiresInHours: 0.5, maxViews: 1 }), 'serverError');
    const link = await service.sharing.createShareLink(item.id, { expiresInHours: 24, maxViews: 2, passphrase: 'blue heron' });
    expect(await service.sharing.listShareLinks()).toMatchObject([{ id: link.id, itemTitle: 'GitHub', views: 0, maxViews: 2, passphraseRequired: true }]);

    await service.signOut();
    const visitor = await MockVaultService.create({ dbName, latency: [0, 0] });
    expect(visitor.getSession().status).toBe('signedOut');
    const envelope = await visitor.sharing.fetchShareLink(DEFAULT_SERVER_URL, link.id);
    expect(envelope).toMatchObject({ passphraseRequired: true, viewsLeft: 1 });
    await expectCode(visitor.sharing.openShareLink(envelope.ciphertext, link.key), 'wrongPassphrase');
    await expectCode(visitor.sharing.openShareLink(envelope.ciphertext, link.key, 'nope'), 'wrongPassphrase');
    await expectCode(visitor.sharing.openShareLink('garbage', link.key), 'invalidShareLink');
    const shared = await visitor.sharing.openShareLink(envelope.ciphertext, link.key, 'blue heron');
    expect(shared.overview.title).toBe('GitHub');
    expect((shared.details as LoginDetails).password).toBeTruthy();

    await visitor.sharing.fetchShareLink(DEFAULT_SERVER_URL, link.id);
    await expectCode(visitor.sharing.fetchShareLink(DEFAULT_SERVER_URL, link.id), 'notFound');
  });

  it('revokes share links', async () => {
    const service = await signedUp();
    const item = (await service.listItems())[0]!;
    const link = await service.sharing.createShareLink(item.id, { expiresInHours: 1, maxViews: 1 });
    await service.sharing.revokeShareLink(link.id);
    expect(await service.sharing.listShareLinks()).toEqual([]);
    await expectCode(service.sharing.fetchShareLink(DEFAULT_SERVER_URL, link.id), 'notFound');
  });

  it('runs emergency access on both sides and logs it', async () => {
    const { sharing } = await signedUp();
    const seeded = await sharing.listEmergencyContacts();
    const leila = seeded.granted[0]!;
    expect(leila.status).toBe('requested');
    await sharing.denyEmergencyAccess(leila.id);
    expect((await sharing.listEmergencyContacts()).granted[0]).toMatchObject({ status: 'idle' });
    expect((await sharing.listEmergencyContacts()).granted[0]!.requestedAt).toBeUndefined();

    const omar = await sharing.addEmergencyContact({ account: await sharing.lookupAccount('omar@example.com'), waitDays: 3, accessLevel: 'view', scope: { type: 'account' } });
    await expectCode(sharing.addEmergencyContact({ account: await sharing.lookupAccount('omar@example.com'), waitDays: 3, accessLevel: 'view', scope: { type: 'account' } }), 'alreadyExists');
    await expectCode(sharing.approveEmergencyAccess(omar.id), 'notAllowed');

    const sam = seeded.received[0]!;
    const view = await sharing.openEmergencyAccess(sam.id);
    expect(view.vaults).toHaveLength(1);
    expect(view.items.length).toBeGreaterThan(0);
    expect(view.items.every((i) => i.vaultId === view.vaults[0]!.id)).toBe(true);
    const withFile = view.items.find((i) => attachmentsOf(i).length)!;
    const file = await sharing.getEmergencyAttachment(sam.id, withFile.id, attachmentsOf(withFile)[0]!.id);
    expect(await file.text()).toContain('Pension statement');
    expect(file.size).toBe(attachmentsOf(withFile)[0]!.size);
    await expectCode(sharing.getEmergencyAttachment(sam.id, withFile.id, 'nope'), 'notFound');
    await expectCode(sharing.getEmergencyAttachment(omar.id, withFile.id, attachmentsOf(withFile)[0]!.id), 'notFound');

    expect((await sharing.getSecurityLog()).map((e) => e.type).slice(0, 2)).toEqual(['emergency-contact-added', 'emergency-access-denied']);
    await sharing.removeEmergencyContact(omar.id);
    expect((await sharing.listEmergencyContacts()).granted.map((c) => c.id)).toEqual([leila.id]);
  });

  it('renames this device and signs out others, never itself', async () => {
    const { sharing } = await signedUp();
    await sharing.renameDevice('  Kitchen iPad ');
    const devices = await sharing.listDevices();
    expect(devices.find((d) => d.current)?.name).toBe('Kitchen iPad');
    await expectCode(sharing.renameDevice(''), 'serverError');
    await expectCode(sharing.signOutDevice(devices.find((d) => d.current)!.id), 'notFound');
    await sharing.signOutDevice(devices.find((d) => !d.current)!.id);
    expect(await sharing.listDevices()).toHaveLength(2);
  });

  it('needs an unlocked vault', async () => {
    const service = await signedUp();
    service.lock();
    await expectCode(service.sharing.listDevices(), 'locked');
    await expectCode(service.sharing.createVault('x'), 'locked');
  });
});
