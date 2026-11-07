import { MockVaultService } from '../mock/MockVaultService';
import type { LoginDetails, MaskedEmailProviderDetails } from '../types';
import type { HttpRequest, MaskedEmailHttp } from './providers';
import { aliasSite, createMaskedEmailService, usableIn } from './service';

let db = 0;
async function unlockedVault() {
  const vault = await MockVaultService.create({ dbName: `masked-${++db}`, latency: [0, 0], seed: false, fetch: async () => new Response('') });
  const { signupId, devVerificationCode } = await vault.startSignup({ serverUrl: 'https://vault.example', email: 'maya@example.com', password: 'correct horse battery staple' });
  await vault.finishSignup({ signupId, verificationCode: devVerificationCode! });
  return vault;
}

function recording(answer: unknown = { alias: 'shop.x1@simplelogin.com', id: 9 }) {
  const sent: HttpRequest[] = [];
  const http: MaskedEmailHttp = async (request) => {
    sent.push(request);
    return { status: 201, headers: {}, body: JSON.stringify(answer) };
  };
  return { http, sent };
}

describe('MaskedEmailService', () => {
  it('keeps the token in a hidden vault item and lists the connection without it', async () => {
    const vault = await unlockedVault();
    const service = createMaskedEmailService(vault, { context: 'extension', http: recording().http });
    const connection = await service.connect({ provider: 'addy', token: '  tok  ', domain: '@Anonaddy.me' });
    expect(connection).toEqual({ itemId: expect.any(String), provider: 'addy', domain: 'anonaddy.me', usableHere: true });
    expect(await service.listConnections()).toEqual([connection]);
    // Hidden from the item lists, but stored like any item.
    expect(await vault.listItems()).toEqual([]);
    const item = await vault.getItem(connection.itemId);
    expect(item.overview).toMatchObject({ type: 'maskedEmailProvider', title: 'addy.io', subtitle: 'anonaddy.me' });
    expect(item.details as MaskedEmailProviderDetails).toEqual({ schemaVersion: 1, provider: 'addy', token: 'tok', domain: 'anonaddy.me' });
  });

  it('checks the input before storing anything', async () => {
    const vault = await unlockedVault();
    const service = createMaskedEmailService(vault, { context: 'app' });
    await expect(service.connect({ provider: 'simplelogin', token: ' ' })).rejects.toMatchObject({ code: 'maskedEmailToken' });
    await expect(service.connect({ provider: 'forwardEmail', token: 't' })).rejects.toMatchObject({ code: 'maskedEmailFailed' });
    await expect(service.connect({ provider: 'simplelogin', token: 't', baseUrl: 'http://sl.example' })).rejects.toMatchObject({ code: 'insecureServerUrl' });
    expect(await service.listConnections()).toEqual([]);
  });

  it('makes an alias for the site with the first connected provider', async () => {
    const vault = await unlockedVault();
    const { http, sent } = recording();
    const service = createMaskedEmailService(vault, { context: 'extension', http });
    await service.connect({ provider: 'simplelogin', token: 'sl', baseUrl: 'https://sl.example' });
    expect(await service.createAlias({ site: 'https://www.shop.example.co.uk/signup' })).toEqual({ email: 'shop.x1@simplelogin.com', aliasId: '9', provider: 'simplelogin' });
    expect(sent[0]!.url).toBe('https://sl.example/api/alias/random/new?hostname=example.co.uk');
  });

  it('deletes an alias, unlinking only logins linked to that alias', async () => {
    const vault = await unlockedVault();
    const { http, sent } = recording({});
    const service = createMaskedEmailService(vault, { context: 'extension', http });
    await service.connect({ provider: 'simplelogin', token: 'sl' });
    const [personal] = await vault.listVaults();
    const save = (aliasId: string) =>
      vault.saveItem({
        vaultId: personal!.id,
        overview: { schemaVersion: 1, type: 'login', title: aliasId },
        details: { schemaVersion: 1, recovery: { email: 'a@sl.co', emailSource: { kind: 'alias', provider: 'simplelogin', aliasId } } },
      });
    const linked = await save('9');
    const other = await save('10');
    await service.deleteAlias({ provider: 'simplelogin', aliasId: '9', email: 'a@sl.co' }, [linked.id, other.id]);
    expect(sent.map((r) => r.method)).toEqual(['DELETE']);
    expect(((await vault.getItem(linked.id)).details as LoginDetails).recovery).toEqual({ email: 'a@sl.co' });
    expect(((await vault.getItem(other.id)).details as LoginDetails).recovery?.emailSource).toEqual({ kind: 'alias', provider: 'simplelogin', aliasId: '10' });
  });

  it('leaves the logins alone when the provider refuses', async () => {
    const vault = await unlockedVault();
    const http: MaskedEmailHttp = async () => ({ status: 401, headers: {}, body: '' });
    const service = createMaskedEmailService(vault, { context: 'extension', http });
    await service.connect({ provider: 'simplelogin', token: 'sl' });
    const [personal] = await vault.listVaults();
    const login = await vault.saveItem({
      vaultId: personal!.id,
      overview: { schemaVersion: 1, type: 'login', title: 'x' },
      details: { schemaVersion: 1, recovery: { email: 'a@sl.co', emailSource: { kind: 'alias', provider: 'simplelogin', aliasId: '9' } } },
    });
    await expect(service.deleteAlias({ provider: 'simplelogin', aliasId: '9', email: 'a@sl.co' }, [login.id])).rejects.toMatchObject({ code: 'maskedEmailToken' });
    expect(((await vault.getItem(login.id)).details as LoginDetails).recovery?.emailSource).toBeDefined();
  });

  it('changes an alias only through a connected provider that works here', async () => {
    const vault = await unlockedVault();
    const { http, sent } = recording({ enabled: true });
    const service = createMaskedEmailService(vault, { context: 'browser', http });
    const relay = { provider: 'firefoxRelay' as const, aliasId: '9', email: 'a@mozmail.com' };
    await expect(service.setAliasEnabled(relay, false)).rejects.toMatchObject({ code: 'maskedEmailNotSetUp' });
    await service.connect({ provider: 'firefoxRelay', token: 'r' });
    await expect(service.setAliasEnabled(relay, false)).rejects.toMatchObject({ code: 'maskedEmailBlocked' });
    await expect(service.setAliasEnabled({ provider: 'duckduckgo', aliasId: 'a@duck.com', email: 'a@duck.com' }, false)).rejects.toMatchObject({ code: 'maskedEmailFailed' });
    expect(sent).toEqual([]);
  });

  it('says why when nothing is set up, or only providers this page can’t reach', async () => {
    const vault = await unlockedVault();
    const { http, sent } = recording();
    const service = createMaskedEmailService(vault, { context: 'browser', http });
    await expect(service.createAlias({ site: 'shop.example' })).rejects.toMatchObject({ code: 'maskedEmailNotSetUp' });
    const relay = await service.connect({ provider: 'firefoxRelay', token: 'r' });
    expect(relay.usableHere).toBe(false);
    await expect(service.createAlias({ site: 'shop.example' })).rejects.toMatchObject({ code: 'maskedEmailBlocked' });
    await expect(service.createAlias({ site: 'shop.example', connectionId: relay.itemId })).rejects.toMatchObject({ code: 'maskedEmailBlocked' });
    expect(sent).toEqual([]);
    // A provider that answers CORS is used instead.
    await service.connect({ provider: 'simplelogin', token: 'sl' });
    expect((await service.createAlias({ site: 'shop.example' })).provider).toBe('simplelogin');
  });

  it('disconnects by moving the token to the trash', async () => {
    const vault = await unlockedVault();
    const service = createMaskedEmailService(vault, { context: 'app' });
    const { itemId } = await service.connect({ provider: 'duckduckgo', token: 'd' });
    await service.disconnect(itemId);
    expect(await service.listConnections()).toEqual([]);
    await expect(service.createAlias({ site: 'shop.example' })).rejects.toMatchObject({ code: 'maskedEmailNotSetUp' });
  });

  it("won't disconnect an item that isn't a provider", async () => {
    const vault = await unlockedVault();
    const [personal] = await vault.listVaults();
    const note = await vault.saveItem({ vaultId: personal!.id, overview: { schemaVersion: 1, type: 'secureNote', title: 'n' }, details: { schemaVersion: 1, notes: '' } });
    await expect(createMaskedEmailService(vault, { context: 'app' }).disconnect(note.id)).rejects.toMatchObject({ code: 'notFound' });
  });
});

describe('helpers', () => {
  it('describes the site by its registrable domain', () => {
    expect(aliasSite('https://accounts.github.com/join')).toEqual({ domain: 'github.com', origin: 'https://accounts.github.com' });
    expect(aliasSite('bbc.co.uk')).toEqual({ domain: 'bbc.co.uk', origin: 'https://bbc.co.uk' });
    expect(() => aliasSite('')).toThrow();
  });

  it('knows which providers a web page can call', () => {
    expect(['simplelogin', 'addy', 'fastmail', 'forwardEmail'].every((p) => usableIn('browser', p as never))).toBe(true);
    expect(usableIn('browser', 'firefoxRelay')).toBe(false);
    expect(usableIn('browser', 'duckduckgo')).toBe(false);
    expect(usableIn('extension', 'duckduckgo')).toBe(true);
    expect(usableIn('app', 'firefoxRelay')).toBe(true);
  });
});
