import { createHealthSettings, type EnvironmentDetails, type LoginDetails } from '@octapass/vault-client';
import { DEFAULT_SERVER_URL, MockVaultService } from '@octapass/vault-client/mock';
import { screen, waitFor, within } from '@testing-library/react';
import { formatDate } from '../../i18n';
import { EMAIL, PASSWORD, renderApp } from '../../test/renderApp';

describe('an imported item', { timeout: 20_000 }, () => {
  it('shows the dates and HTTP realm the other app recorded', async () => {
    const service = await MockVaultService.create({ dbName: 'item-detail-dates', latency: [0, 0], seed: false, fetch: async () => new Response('') });
    const { signupId, devVerificationCode } = await service.startSignup({ serverUrl: DEFAULT_SERVER_URL, email: EMAIL, password: PASSWORD });
    await service.finishSignup({ signupId, verificationCode: devVerificationCode! });
    const [vault] = await service.listVaults();
    const item = await service.saveItem({
      vaultId: vault!.id,
      overview: {
        schemaVersion: 1,
        type: 'login',
        title: 'Router',
        urls: ['http://192.168.0.1'],
        createdAt: '2019-03-04T10:00:00Z',
        updatedAt: '2021-07-08T10:00:00Z',
        lastUsedAt: '2024-02-03T10:00:00Z',
        importedFrom: { source: 'firefox', id: '{6a7e1f4e}' },
      },
      details: { schemaVersion: 1, username: 'admin', password: 'admin', httpRealm: 'Router Admin', passwordChangedAt: '2021-07-08T10:00:00Z' } as LoginDetails,
    });
    renderApp(service, `/items/all/${item.id}`);
    expect(await screen.findByText('Router Admin')).toBeInTheDocument();
    expect(screen.getByText('HTTP realm')).toBeInTheDocument();
    expect(screen.getByText(`Created ${formatDate('2019-03-04T10:00:00Z')}`)).toBeInTheDocument();
    expect(screen.getByText(`Last changed ${formatDate('2021-07-08T10:00:00Z', 'long')}`)).toBeInTheDocument();
    expect(screen.getByText(`Password changed ${formatDate('2021-07-08T10:00:00Z')}`)).toBeInTheDocument();
    expect(screen.getByText(`Last used ${formatDate('2024-02-03T10:00:00Z')}`)).toBeInTheDocument();
  });
});


describe('an environment', { timeout: 20_000 }, () => {
  it('hides values, marks production and copies the .env text', async () => {
    const service = await MockVaultService.create({ dbName: 'item-detail-env', latency: [0, 0], seed: false, fetch: async () => new Response('') });
    const { signupId, devVerificationCode } = await service.startSignup({ serverUrl: DEFAULT_SERVER_URL, email: EMAIL, password: PASSWORD });
    await service.finishSignup({ signupId, verificationCode: devVerificationCode! });
    const [vault] = await service.listVaults();
    const item = await service.saveItem({
      vaultId: vault!.id,
      overview: { schemaVersion: 1, type: 'environment', title: 'Shop API' },
      details: {
        schemaVersion: 1,
        project: 'shop-api',
        stage: 'production',
        variables: [
          { key: 'DATABASE_URL', value: 'postgres://secret', concealed: true },
          { key: 'PORT', value: '8080', concealed: true },
        ],
      } as EnvironmentDetails,
    });
    const { user } = renderApp(service, `/items/all/${item.id}`);
    expect(await screen.findByRole('heading', { name: 'Shop API' })).toBeInTheDocument();
    expect(screen.queryByText('postgres://secret')).not.toBeInTheDocument();
    expect(screen.getByText(/This is production/)).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Copy as .env' }));
    expect(await navigator.clipboard.readText()).toBe('DATABASE_URL=postgres://secret\nPORT=8080\n');
  });
});


describe('a login password', { timeout: 20_000 }, () => {
  it('shows it without asking while the vault is open, even on a device with no device unlock (maintainer decision, 2026-11-06)', async () => {
    const service = await MockVaultService.create({ dbName: 'item-detail-reveal', latency: [0, 0], seed: false, fetch: async () => new Response('') });
    const { signupId, devVerificationCode } = await service.startSignup({ serverUrl: DEFAULT_SERVER_URL, email: EMAIL, password: PASSWORD });
    await service.finishSignup({ signupId, verificationCode: devVerificationCode! });
    const [vault] = await service.listVaults();
    const item = await service.saveItem({
      vaultId: vault!.id,
      overview: { schemaVersion: 1, type: 'login', title: 'Shop', urls: ['https://shop.example'] },
      details: { schemaVersion: 1, username: 'maya', password: 'orchid-quartz-77' } as LoginDetails,
    });
    const { user } = renderApp(service, `/items/all/${item.id}`);
    expect(await screen.findByRole('heading', { name: 'Shop' })).toBeInTheDocument();
    expect(screen.queryByText('orchid-quartz-77')).not.toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: /show password/i }));
    expect(await screen.findByText('orchid-quartz-77')).toBeInTheDocument();
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });
});

describe('a login from several apps', { timeout: 20_000 }, () => {
  async function signedIn(dbName: string) {
    const service = await MockVaultService.create({ dbName, latency: [0, 0], seed: false, fetch: async () => new Response('') });
    const { signupId, devVerificationCode } = await service.startSignup({ serverUrl: DEFAULT_SERVER_URL, email: EMAIL, password: PASSWORD });
    await service.finishSignup({ signupId, verificationCode: devVerificationCode! });
    const [vault] = await service.listVaults();
    const login = (title: string, urls: string[], username: string) =>
      service.saveItem({
        vaultId: vault!.id,
        overview: { schemaVersion: 1, type: 'login', title, urls, subtitle: username },
        details: { schemaVersion: 1, username, password: 'correct-horse-shared' } as LoginDetails,
      });
    const item = await login('Saasify', ['https://saasify.example.com', 'https://saasify.example.com/', 'http://www.saasify.example.com/login', 'https://other.example'], 'ada');
    await login('Forum', ['https://forum.example/login'], 'ada@forum');
    await login('Shop', ['https://shop.example'], 'ada@shop');
    return { service, item };
  }

  it('lists each website once', async () => {
    const { service, item } = await signedIn('item-detail-websites');
    renderApp(service, `/items/all/${item.id}`);
    expect(await screen.findByRole('heading', { name: 'Saasify' })).toBeInTheDocument();
    const sites = screen.getAllByRole('link', { name: /example/ }).map((link) => link.getAttribute('href'));
    expect(sites).toEqual(['https://saasify.example.com', 'https://other.example']);
    expect(screen.getAllByText('Also used on')).toHaveLength(1);
  });

  it('says the password is used on other logins and lists them with a way to change each', async () => {
    const { service, item } = await signedIn('item-detail-reused');
    const { user } = renderApp(service, `/items/all/${item.id}`);
    expect(await screen.findByText('Password used on 2 other logins')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'See them' }));
    const list = await screen.findByRole('dialog', { name: 'Logins with this password' });
    expect(within(list).getByText('Forum')).toBeInTheDocument();
    expect(within(list).getByText('ada@forum · forum.example')).toBeInTheDocument();
    expect(within(list).getByText('Shop')).toBeInTheDocument();
    expect(within(list).queryByText('Saasify')).not.toBeInTheDocument();
    const changes = within(list).getAllByRole('link', { name: 'Change password' });
    expect(changes.map((link) => link.getAttribute('href'))).toEqual(['https://forum.example/.well-known/change-password', 'https://shop.example/.well-known/change-password']);
  });

  it('says nothing when the group was dismissed in Health', async () => {
    const { service, item } = await signedIn('item-detail-reused-dismissed');
    const report = await service.getHealthReport();
    await createHealthSettings(service).dismiss(report.reused[0]!.map((entry) => entry.warning!));
    renderApp(service, `/items/all/${item.id}`);
    expect(await screen.findByRole('heading', { name: 'Saasify' })).toBeInTheDocument();
    await waitFor(() => expect(screen.getAllByText('Also used on')).toHaveLength(1));
    expect(screen.queryByText(/Password used on/)).not.toBeInTheDocument();
  });
});
