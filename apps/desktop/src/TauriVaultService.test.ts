import { isVaultError, type ItemSummary } from '@octapass/vault-client';
import { describe, expect, it, vi } from 'vitest';
import { FakeTransport } from './test/fakeTransport';
import { TauriVaultService, type HealthInputs, type SessionSnapshot } from './TauriVaultService';

const locked: SessionSnapshot = {
  session: { status: 'locked', email: 'ada@example.com', serverUrl: 'http://localhost:8080' },
  rememberedAccounts: [{ email: 'ada@example.com', serverUrl: 'http://localhost:8080' }],
};
const unlocked: SessionSnapshot = { ...locked, session: { ...locked.session, status: 'unlocked' } };

function row(id: string, title: string, extra: Partial<ItemSummary> = {}): ItemSummary {
  return { id, vaultId: 'v', type: 'login', title, favorite: false, hasTotp: false, hasPasskey: false, createdAt: '2026-10-24T00:00:00Z', updatedAt: '2026-10-24T00:00:00Z', ...extra };
}

async function connect(snapshot: SessionSnapshot = unlocked, setup: (t: FakeTransport) => void = () => {}) {
  const transport = new FakeTransport().on('session_snapshot', () => snapshot);
  setup(transport);
  return { transport, service: await TauriVaultService.create(transport) };
}

describe('TauriVaultService', () => {
  it('starts from the Rust session and follows its events', async () => {
    const { transport, service } = await connect(locked);
    expect(service.getSession().status).toBe('locked');
    expect(service.rememberedAccounts()).toEqual(locked.rememberedAccounts);

    const changes = vi.fn();
    service.onSessionChange(changes);
    transport.emit('vault://session', unlocked);
    expect(service.getSession().status).toBe('unlocked');
    expect(changes).toHaveBeenCalledOnce();
    transport.emit('vault://session', unlocked);
    expect(changes).toHaveBeenCalledOnce();
  });

  it('locks the page at once and tells Rust', async () => {
    const { transport, service } = await connect(unlocked, (t) => t.on('lock', () => undefined));
    service.lock();
    expect(service.getSession().status).toBe('locked');
    expect(transport.calls.at(-1)?.command).toBe('lock');
  });

  it('takes `confirmed` from Rust, until the vault locks (plan 03 History 2026-11-05, plan 18)', async () => {
    const { transport, service } = await connect(locked, (t) => t.on('lock', () => undefined));
    expect(service.getSession().confirmed).toBeUndefined();
    // The master password or the device lock opened it.
    transport.emit('vault://session', { ...unlocked, session: { ...unlocked.session, confirmed: true } });
    expect(service.getSession()).toEqual({ ...unlocked.session, confirmed: true });
    service.lock();
    expect(service.getSession()).toEqual(locked.session);

    // Stay unlocked opened it: the first reveal asks, and its answer is heard as a change.
    const changes = vi.fn();
    service.onSessionChange(changes);
    transport.emit('vault://session', unlocked);
    expect(service.getSession().confirmed).toBeUndefined();
    transport.emit('vault://session', { ...unlocked, session: { ...unlocked.session, confirmed: true } });
    expect(service.getSession().confirmed).toBe(true);
    // A screen lock while staying unlocked.
    transport.emit('vault://session', unlocked);
    expect(service.getSession().confirmed).toBeUndefined();
    expect(changes).toHaveBeenCalledTimes(3);
  });

  it('passes stay unlocked to Rust (plan 18)', async () => {
    const status = { on: true, available: true, enrolled: true, passwordRequired: false };
    const { transport, service } = await connect(locked, (t) =>
      t
        .on('stay_unlocked_status', () => status)
        .on('set_stay_unlocked', () => ({ ...status, on: false, enrolled: false }))
        .on('unlock_stay_unlocked', () => true),
    );
    expect(await service.getStayUnlocked()).toEqual(status);
    expect((await service.setStayUnlocked(false)).on).toBe(false);
    expect(transport.calls.at(-1)).toMatchObject({ command: 'set_stay_unlocked', args: { on: false } });
    expect(await service.unlockStayUnlocked()).toBe(true);
  });

  it('turns command errors into VaultErrors and unexpected ones into plain errors', async () => {
    const { service } = await connect(locked, (t) =>
      t
        .on('unlock', () => Promise.reject({ code: 'invalidCredentials', message: 'InvalidCredentials' }))
        .on('sign_out', () => Promise.reject({ code: 'unexpected', message: 'storage: disk full' })),
    );
    const wrong = await service.unlock('nope').catch((error: unknown) => error);
    expect(isVaultError(wrong, 'invalidCredentials')).toBe(true);
    const failed = await service.signOut().catch((error: unknown) => error);
    expect(isVaultError(failed)).toBe(false);
    expect((failed as Error).message).toBe('storage: disk full');
  });

  it('passes arguments in the shape the commands expect', async () => {
    const { transport, service } = await connect(unlocked, (t) => t.on('sign_in', () => ({ status: 'signedIn' })).on('totp_code', () => ({ code: '123456', period: 30, remaining: 4 })));
    expect(await service.signIn({ serverUrl: 'http://localhost:8080', email: 'ada@example.com', password: 'pw' })).toEqual({ status: 'signedIn' });
    expect(transport.calls.at(-1)?.args).toEqual({ serverUrl: 'http://localhost:8080', email: 'ada@example.com', password: 'pw', secretKey: null });
    expect(await service.totpCode('JBSWY3DPEHPK3PXP')).toEqual({ code: '123456', period: 30, remaining: 4 });
    expect(transport.calls.at(-1)?.args).toEqual({ totp: 'JBSWY3DPEHPK3PXP', at: null });
  });

  it('signs in with a second step', async () => {
    const { transport, service } = await connect(locked, (t) =>
      t
        .on('sign_in', () => ({ status: 'twoStepRequired', methods: ['totp', 'recoveryCode'] }))
        .on('finish_two_step', (args) =>
          (args!.proof as { code?: string }).code === '123456'
            ? undefined
            : Promise.reject({ code: 'invalidTwoStepCode', message: 'InvalidTwoStepCode' }),
        ),
    );
    const result = await service.signIn({ serverUrl: 'http://localhost:8080', email: 'ada@example.com', password: 'pw' });
    expect(result).toEqual({ status: 'twoStepRequired', methods: ['totp', 'recoveryCode'] });
    const wrong = await service.finishTwoStep({ method: 'totp', code: '000000' }).catch((error: unknown) => error);
    expect(isVaultError(wrong, 'invalidTwoStepCode')).toBe(true);
    await service.finishTwoStep({ method: 'totp', code: '123456' });
    expect(transport.calls.at(-1)).toEqual({ command: 'finish_two_step', args: { proof: { method: 'totp', code: '123456' } } });
  });

  it('runs the two-step settings commands, without security keys', async () => {
    const status = { enabled: true, securityKeys: [{ id: 'k', name: 'YubiKey', createdAt: '2026-10-24T00:00:00Z' }], recoveryCodesLeft: 10, securityKeysSupported: false };
    const { transport, service } = await connect(unlocked, (t) =>
      t
        .on('two_step_status', () => status)
        .on('start_totp_setup', () => ({ secret: 'JBSWY3DPEHPK3PXP', otpauthUri: 'otpauth://totp/Open%20Pass:ada?secret=JBSWY3DPEHPK3PXP' }))
        .on('confirm_totp_setup', () => ({ recoveryCodes: ['ABCDE-12345'] }))
        .on('renew_recovery_codes', () => ['FGHIJ-67890'])
        .on('disable_two_step', () => undefined)
        .on('remove_security_key', () => undefined),
    );
    const twoStep = service.twoStep;
    expect(await twoStep.getTwoStepStatus()).toEqual(status);
    expect((await twoStep.startTotpSetup('pw')).secret).toBe('JBSWY3DPEHPK3PXP');
    expect(transport.calls.at(-1)).toEqual({ command: 'start_totp_setup', args: { password: 'pw' } });
    expect(await twoStep.confirmTotpSetup('123456')).toEqual({ recoveryCodes: ['ABCDE-12345'] });
    expect(transport.calls.at(-1)?.args).toEqual({ code: '123456' });
    expect(await twoStep.renewRecoveryCodes('pw')).toEqual(['FGHIJ-67890']);
    await twoStep.removeSecurityKey({ id: 'k', password: 'pw' });
    expect(transport.calls.at(-1)).toEqual({ command: 'remove_security_key', args: { id: 'k', password: 'pw' } });
    await twoStep.disableTwoStep('pw');
    expect(transport.calls.at(-1)).toEqual({ command: 'disable_two_step', args: { password: 'pw' } });

    const calls = transport.calls.length;
    const added = await twoStep.addSecurityKey({ password: 'pw', name: 'YubiKey' }).catch((error: unknown) => error);
    expect(isVaultError(added, 'securityKeyUnsupported')).toBe(true);
    expect(transport.calls).toHaveLength(calls);
  });

  it('filters and sorts the rows Rust returns', async () => {
    const rows = [row('2', 'Zebra'), row('1', 'apple', { favorite: true }), row('3', 'Bank', { deletedAt: '2026-10-24T00:00:00Z' })];
    const { service } = await connect(unlocked, (t) => t.on('list_items', () => rows));
    expect((await service.listItems()).map((r) => r.title)).toEqual(['apple', 'Zebra']);
    expect((await service.listItems({ favorites: true })).map((r) => r.id)).toEqual(['1']);
    expect((await service.listItems({ trash: true })).map((r) => r.id)).toEqual(['3']);
    expect((await service.listItems({ query: 'zeb' })).map((r) => r.id)).toEqual(['2']);
  });

  it('notifies item listeners on the items-changed event', async () => {
    const { transport, service } = await connect();
    const changed = vi.fn();
    const stop = service.onItemsChange(changed);
    transport.emit('vault://items-changed', null);
    stop();
    transport.emit('vault://items-changed', null);
    expect(changed).toHaveBeenCalledOnce();
  });

  it('builds the new health checks from counts and dates, and reads dismissals from the vault', async () => {
    const inputs: HealthInputs = {
      logins: [
        {
          itemId: 'a',
          vaultId: 'v',
          type: 'login',
          title: 'Forum',
          urls: ['http://forum.example'],
          hasTotp: false,
          hasPasskey: false,
          passwordGroup: 0,
          passwordDate: '2020-01-01T00:00:00.000Z',
          backupCodes: { total: 5, unused: 1 },
        },
        { itemId: 'b', vaultId: 'v', type: 'login', title: 'Shop', urls: ['http://shop.example'], hasTotp: false, hasPasskey: false, passwordGroup: 1, passwordDate: '2026-10-01T00:00:00.000Z' },
      ],
      expiries: [{ itemId: 'c', vaultId: 'v', type: 'card', title: 'Visa', expiry: '01/20' }],
      groups: [
        { score: 4, breachCount: 0 },
        { score: 4, breachCount: 0 },
      ],
      breachCheckCompleted: true,
      settings: { schemaVersion: 1, dismissed: ['insecureUrl:b:http://shop.example'] },
    };
    const { service } = await connect(unlocked, (t) => t.on('health_inputs', () => inputs));
    const report = await service.getHealthReport();
    expect(report.insecureUrls.map((e) => e.title)).toEqual(['Forum']);
    expect(report.dismissed.map((e) => e.title)).toEqual(['Shop']);
    expect(report.old.map((e) => e.title)).toEqual(['Forum']);
    expect(report.lowBackupCodes).toMatchObject([{ title: 'Forum', unused: 1 }]);
    expect(report.expiring).toMatchObject([{ title: 'Visa', expiresOn: '2020-01-31' }]);
  });

  it('builds the health report from password groups, without passwords', async () => {
    const inputs: HealthInputs = {
      logins: [
        { itemId: 'a', vaultId: 'v', type: 'login', title: 'A', subtitle: 'ada', urls: ['https://github.com'], hasTotp: false, hasPasskey: false, passwordGroup: 0 },
        { itemId: 'b', vaultId: 'v', type: 'login', title: 'B', hasTotp: true, hasPasskey: false, passwordGroup: 0 },
        { itemId: 'c', vaultId: 'v', type: 'login', title: 'C', hasTotp: false, hasPasskey: false, passwordGroup: 1 },
        { itemId: 'd', vaultId: 'v', type: 'login', title: 'No password', hasTotp: false, hasPasskey: false },
      ],
      groups: [
        { score: 0, breachCount: 12 },
        { score: 4, breachCount: 0 },
      ],
      breachCheckCompleted: true,
    };
    const { service } = await connect(unlocked, (t) => t.on('health_inputs', () => inputs));
    const report = await service.getHealthReport();
    expect(report.checked).toBe(3);
    expect(report.weak.map((entry) => entry.itemId)).toEqual(['a', 'b']);
    expect(report.reused).toHaveLength(1);
    expect(report.reused[0]!.map((entry) => entry.itemId)).toEqual(['a', 'b']);
    expect(report.breached.map((entry) => [entry.itemId, entry.count])).toEqual([
      ['a', 12],
      ['b', 12],
    ]);
    expect(report.breachCheckCompleted).toBe(true);
    expect(report.missing2fa.map((entry) => entry.itemId)).toEqual(['a']);
    expect(report.weak[0]!.subtitle).toBe('ada');
  });

  it('builds the recovery map from recovery emails and usernames', async () => {
    const inputs: HealthInputs = {
      logins: [
        { itemId: 'g', vaultId: 'v', type: 'login', title: 'Google', urls: ['https://accounts.google.com'], username: 'ali@gmail.com', hasTotp: false, hasPasskey: false },
        { itemId: 'b', vaultId: 'v', type: 'login', title: 'Bank', hasTotp: false, hasPasskey: false, recovery: { email: 'ali@gmail.com', emailSource: { kind: 'identity', itemId: 'me' } } },
        { itemId: 's', vaultId: 'v', type: 'login', title: 'Shop', username: 'ali@gmail.com', hasTotp: false, hasPasskey: false, twoFactorMethod: 'sms', recovery: { phone: '+1 555' } },
      ],
      groups: [],
      breachCheckCompleted: true,
    };
    const { service } = await connect(unlocked, (t) => t.on('health_inputs', () => inputs));
    const report = await service.getHealthReport();
    expect(report.recovery.map((c) => [c.value, c.logins.map((l) => l.itemId), c.identityId])).toEqual([
      ['ali@gmail.com', ['b', 's'], 'me'],
      ['+1 555', ['s'], undefined],
    ]);
    expect(report.recoveryNo2fa).toEqual([expect.objectContaining({ itemId: 'g', email: 'ali@gmail.com', accounts: 2 })]);
  });

  it('runs local vaults through their commands, only where the app has them', async () => {
    const transport = new FakeTransport().on('session_snapshot', () => ({ session: { status: 'signedOut' }, rememberedAccounts: [] }));
    const phone = await TauriVaultService.create(transport);
    expect(phone.local).toBeUndefined();
    expect(phone.setFillGate).toBeUndefined();

    transport
      .on('create_local_vault', () => 'code')
      .on('restore_local_vault', () => undefined)
      .on('save_local_backup', () => null)
      .on('choose_backup_folder', () => '/Backups')
      .on('set_fill_gate', () => undefined);
    const service = await TauriVaultService.create(transport, { local: true, fillGate: true });
    expect(await service.local!.create({ name: 'Home', password: 'pw' })).toBe('code');
    expect(transport.calls.at(-1)).toEqual({ command: 'create_local_vault', args: { name: 'Home', password: 'pw' } });

    await service.local!.restore(new Uint8Array([1]), { recoveryCode: 'a b', newPassword: 'pw&1' });
    expect(transport.calls.at(-1)!.args!.headers).toEqual({ 'x-backup-code': 'a%20b', 'x-backup-new-password': 'pw%261' });
    await service.local!.restore(new Uint8Array([1]), { password: 'pw' });
    expect(transport.calls.at(-1)!.args!.headers).toEqual({ 'x-backup-password': 'pw' });

    // Cancelling the save dialog isn't a backup.
    expect(await service.local!.saveBackup()).toBeUndefined();
    expect(await service.local!.chooseBackupFolder()).toBe('/Backups');
    await service.setFillGate!(false);
    expect(transport.calls.at(-1)).toEqual({ command: 'set_fill_gate', args: { on: false } });
  });

  it('asks for website icons from the Rust side', async () => {
    const asked: unknown[] = [];
    const { service } = await connect(unlocked, (t) => {
      t.on('site_icon', (args) => {
        asked.push(args);
        const { domain } = args as { domain: string };
        if (domain === 'bank.com') return { status: 200, contentType: 'image/png', retryAfter: null, body: [0x89, 0x50] };
        if (domain === 'busy.com') return { status: 429, contentType: 'application/problem+json', retryAfter: '9', body: [] };
        return { status: 0, contentType: '', retryAfter: null, body: [] };
      });
    });
    expect(await service.fetchSiteIcon('http://localhost:8080', 'bank.com')).toEqual({ kind: 'icon', png: new Uint8Array([0x89, 0x50]) });
    expect(await service.fetchSiteIcon('http://localhost:8080', 'busy.com')).toEqual({ kind: 'retry', retryAfterMs: 9000 });
    expect(await service.fetchSiteIcon('http://localhost:8080', 'down.com')).toEqual({ kind: 'retry' });
    expect(asked[0]).toEqual({ serverUrl: 'http://localhost:8080', domain: 'bank.com' });
  });

  it('confirms identity through Rust for a reveal, copy or export', async () => {
    const { transport, service } = await connect(unlocked, (t) =>
      t
        .on('confirm_master_password', () => undefined)
        .on('confirm_with_device', () => undefined)
        .on('unlock_methods', () => ({ deviceUnlockSupported: true, deviceUnlockEnabled: true, label: 'Touch ID', platform: 'mac', passwordRequired: false })),
    );
    await service.confirmIdentity({ password: 'master' });
    expect(transport.calls.at(-1)).toEqual({ command: 'confirm_master_password', args: { password: 'master' } });
    await service.confirmIdentity({ device: true });
    expect(transport.calls.at(-1)).toEqual({ command: 'confirm_with_device', args: undefined });
    expect(await service.canConfirmIdentityWithDevice()).toBe(true);
  });

  it('calls the providers natively, and self-hosted servers through the web view', async () => {
    const requests: unknown[] = [];
    const { service } = await connect(unlocked, (t) => {
      t.on('list_items', () => [{ id: 'p', vaultId: 'v1', type: 'maskedEmailProvider', title: 'Firefox Relay', favorite: false, hasTotp: false, hasPasskey: false, createdAt: '', updatedAt: '' }]);
      t.on('get_item', () => ({ id: 'p', vaultId: 'v1', revision: 1, createdAt: '', updatedAt: '', overview: { schemaVersion: 1, type: 'maskedEmailProvider', title: 'Firefox Relay' }, details: { schemaVersion: 1, provider: 'firefoxRelay', token: 'tok' } }));
      t.on('masked_email_request', (args) => {
        requests.push(args);
        return { status: 201, headers: {}, body: JSON.stringify({ id: 3, full_address: 'r1@mozmail.com' }) };
      });
    });
    expect(service.maskedEmail.context).toBe('app');
    expect(await service.maskedEmail.createAlias({ site: 'https://shop.example' })).toEqual({ email: 'r1@mozmail.com', aliasId: '3', provider: 'firefoxRelay' });
    expect(requests).toEqual([{ request: expect.objectContaining({ url: 'https://relay.firefox.com/api/v1/relayaddresses/', headers: expect.objectContaining({ Authorization: 'Token tok' }) }) }]);
  });

  it('reports an incomplete breach check', async () => {
    const inputs: HealthInputs = {
      logins: [{ itemId: 'a', vaultId: 'v', type: 'login', title: 'A', hasTotp: false, hasPasskey: false, passwordGroup: 0 }],
      groups: [{ score: 4 }],
      breachCheckCompleted: false,
    };
    const { service } = await connect(unlocked, (t) => t.on('health_inputs', () => inputs));
    const report = await service.getHealthReport();
    expect(report.breachCheckCompleted).toBe(false);
    expect(report.breached).toEqual([]);
  });

  it('imports and makes the core exports in Rust, and the plaintext ones from what Rust decrypts', async () => {
    const vaults = [{ id: 'v1', name: 'Personal', type: 'personal', role: 'owner' }];
    const item = {
      id: 'i', vaultId: 'v1', revision: 1, createdAt: '2026-10-24T00:00:00Z', updatedAt: '2026-10-24T00:00:00Z',
      overview: { schemaVersion: 1, type: 'login', title: 'Example', urls: ['https://example.com'] },
      details: { schemaVersion: 1, username: 'ada', password: 'pw' },
    };
    const { transport, service } = await connect(unlocked, (t) =>
      t
        .on('list_vaults', () => vaults)
        .on('import_file', () => ({ imported: 1, skipped: 0, warnings: [], files: 2 }))
        .on('export_items', () => [item])
        .on('export_file', () => new Uint8Array([79, 80, 69, 88]).buffer)
        .on('record_export', () => undefined)
        .on('unlock', () => undefined),
    );
    const csv = 'name,url,username,password\nExample,https://example.com,ada,pw\n';
    const result = await service.importFile('keepass', new File([csv], 'passwords.csv'), { password: 'p å', keyFile: new Blob([new Uint8Array([1, 2])]) });
    expect(result).toEqual({ imported: 1, skipped: 0, warnings: [], files: 2 });
    const sent = transport.calls.find((call) => call.command === 'import_file')!.args!;
    expect(new TextDecoder().decode(sent.bytes as Uint8Array)).toBe(csv);
    expect(sent.headers).toEqual({ 'x-import-source': 'keepass', 'x-import-password': 'p%20%C3%A5', 'x-import-key-file': 'AQI' });

    const exported = await (await service.exportVault('csv', { masterPassword: 'master' })).text();
    expect(exported).toContain('Example');
    expect(exported).toContain('pw');
    expect(transport.calls.find((call) => call.command === 'unlock')!.args).toEqual({ password: 'master' });

    const encrypted = await service.exportVault('encrypted', { password: 'file password', masterPassword: 'master' });
    expect(new TextDecoder().decode(await encrypted.arrayBuffer())).toBe('OPEX');
    expect(transport.calls.find((call) => call.command === 'export_file')!.args).toEqual({ format: 'encrypted', password: 'file password', masterPassword: 'master' });
    // Each export goes in the security log, with only its format.
    expect(transport.calls.filter((call) => call.command === 'record_export').map((call) => call.args)).toEqual([{ format: 'csv' }, { format: 'encrypted' }]);
  });

  it('still exports when the security log can’t be reached', async () => {
    const { transport, service } = await connect(unlocked, (t) =>
      t
        .on('export_file', () => new Uint8Array([123, 125]).buffer)
        .on('record_export', () => {
          throw { code: 'network', message: 'offline' };
        }),
    );
    expect(await (await service.exportVault('cxf')).text()).toBe('{}');
    expect(transport.calls.some((call) => call.command === 'record_export')).toBe(true);
  });

  it('offers auto-type settings only in the desktop app', async () => {
    const { service: phone } = await connect();
    expect(phone.autoType).toBeUndefined();
    const transport = new FakeTransport().on('session_snapshot', () => unlocked);
    const desktop = await TauriVaultService.create(transport, { autoType: true });
    expect(desktop.autoType?.shortcut).toMatch(/\\$/);
  });

  it('has attachments only where the Rust side does, and sends files as raw bytes', async () => {
    const { service: phone } = await connect();
    expect(phone.attachments).toBeUndefined();

    const transport = new FakeTransport().on('session_snapshot', () => unlocked);
    const desktop = await TauriVaultService.create(transport, { attachments: true });
    expect(desktop.attachments).toBe(desktop);
    const item = { id: 'i', vaultId: 'v', revision: 2, createdAt: '', updatedAt: '', overview: { schemaVersion: 1, type: 'document', title: 'Lease' }, details: { schemaVersion: 1, attachments: [{ id: 'a', name: 'Bail été.pdf', type: 'application/pdf', size: 3, key: 'k' }] } };
    transport.on('add_attachment', () => item).on('get_item', () => item).on('get_attachment', () => new Uint8Array([1, 2, 3]).buffer);

    await desktop.addAttachment('i', new Blob([new Uint8Array([1, 2, 3])], { type: 'application/pdf' }), 'Bail été.pdf');
    const sent = transport.calls.find((call) => call.command === 'add_attachment')!.args as { bytes: Uint8Array; headers: Record<string, string> };
    expect(Array.from(sent.bytes)).toEqual([1, 2, 3]);
    expect(sent.headers).toEqual({ 'x-attachment-item': 'i', 'x-attachment-name': 'Bail%20%C3%A9t%C3%A9.pdf', 'x-attachment-type': 'application%2Fpdf' });

    const file = await desktop.getAttachment('i', 'a');
    expect(file.type).toBe('application/pdf');
    expect(Array.from(new Uint8Array(await file.arrayBuffer()))).toEqual([1, 2, 3]);
  });

  it('hands files to the phone app\'s own pickers and viewer by description only', async () => {
    const transport = new FakeTransport().on('session_snapshot', () => unlocked).on('file_sources', () => ['files', 'photos']);
    const phone = await TauriVaultService.create(transport, { attachments: true, nativeFiles: true });
    const native = phone.attachments!.native!;
    expect(native.sources).toEqual(['files', 'photos']);
    const desktop = await TauriVaultService.create(new FakeTransport().on('session_snapshot', () => unlocked), { attachments: true });
    expect(desktop.attachments!.native).toBeUndefined();

    const picked = { id: 'p1', name: 'Bail été.pdf', type: 'application/pdf', size: 3 };
    transport
      .on('pick_files', () => [picked])
      .on('attach_picked', () => ({ id: 'i' }))
      .on('discard_picked', () => undefined)
      .on('open_attachment', () => Promise.reject({ code: 'noFileViewer', message: 'NoFileViewer' }));
    expect(await native.pick('photos')).toEqual([picked]);
    expect(transport.calls.at(-1)?.args).toEqual({ source: 'photos' });
    await native.attachPicked('i', picked);
    expect(transport.calls.at(-1)?.args).toEqual({ itemId: 'i', pickedId: 'p1' });
    await native.discardPicked([picked]);
    expect(transport.calls.at(-1)?.args).toEqual({ pickedIds: ['p1'] });
    const failed = await native.open('i', 'a').catch((error: unknown) => error);
    expect(isVaultError(failed, 'noFileViewer')).toBe(true);
    expect(transport.calls.at(-1)?.args).toEqual({ itemId: 'i', attachmentId: 'a' });
  });
  it('reviews an import in Rust and finishes it with the chosen links', async () => {
    const review = { id: 'r1', codes: [{ index: 0, title: 'GitHub', issuer: 'GitHub', account: 'ada', loginId: 'g' }], otherItems: 0, skipped: 0, warnings: [] };
    const { transport, service } = await connect(unlocked, (t) =>
      t
        .on('review_import', () => review)
        .on('finish_import', (args) => (args!.reviewId === 'r1' ? { imported: 1, skipped: 0, warnings: [] } : Promise.reject({ code: 'importReviewExpired', message: 'ImportReviewExpired' })))
        .on('cancel_import', () => undefined),
    );
    const text = 'otpauth://totp/GitHub:ada?secret=JBSWY3DPEHPK3PXP&issuer=GitHub\n';
    expect(await service.reviewImport('aegis', new Blob([text]), { password: 'p å' })).toEqual(review);
    const sent = transport.calls.find((call) => call.command === 'review_import')!.args!;
    expect(new TextDecoder().decode(sent.bytes as Uint8Array)).toBe(text);
    expect(sent.headers).toEqual({ 'x-import-source': 'aegis', 'x-import-password': 'p%20%C3%A5' });

    expect(await service.finishImport('r1', [{ code: 0 }])).toEqual({ imported: 1, skipped: 0, warnings: [] });
    expect(transport.calls.at(-1)).toEqual({ command: 'finish_import', args: { reviewId: 'r1', links: [{ code: 0 }] } });
    const expired = await service.finishImport('gone', []).catch((error: unknown) => error);
    expect(isVaultError(expired, 'importReviewExpired')).toBe(true);
    await service.cancelImport('r1');
    expect(transport.calls.at(-1)).toEqual({ command: 'cancel_import', args: { reviewId: 'r1' } });
  });

  it('reads QR codes in Rust from the image\'s raw bytes', async () => {
    const scan = { codes: [{ uri: 'otpauth://totp/x?secret=JBSWY3DPEHPK3PXP', counterBased: false }], incomplete: [], other: 0, broken: 0 };
    const { transport, service } = await connect(unlocked, (t) =>
      t
        .on('read_qr_codes', (args) => ((args!.bytes as Uint8Array)[0] === 0x89 ? ['otpauth://totp/x?secret=JBSWY3DPEHPK3PXP'] : Promise.reject({ code: 'invalidImage', message: 'invalid_image' })))
        .on('summarize_qr_scans', () => scan),
    );
    expect(await service.readQrCodes(new Blob([new Uint8Array([0x89, 0x50])]))).toEqual(['otpauth://totp/x?secret=JBSWY3DPEHPK3PXP']);
    const invalid = await service.readQrCodes(new Blob(['text'])).catch((error: unknown) => error);
    expect(isVaultError(invalid, 'invalidImage')).toBe(true);
    expect(await service.summarizeQrScans(['otpauth://totp/x?secret=JBSWY3DPEHPK3PXP'])).toEqual(scan);
    expect(transport.calls.at(-1)).toEqual({ command: 'summarize_qr_scans', args: { texts: ['otpauth://totp/x?secret=JBSWY3DPEHPK3PXP'] } });
  });

  it('offers the app\'s own QR capture, with command errors as VaultErrors', async () => {
    const { service: plain } = await connect();
    expect(plain.qrCapture).toBeUndefined();

    const transport = new FakeTransport().on('session_snapshot', () => unlocked);
    const results: (string[] | null)[] = [['otpauth://totp/x?secret=JBSWY3DPEHPK3PXP'], null];
    const desktop = await TauriVaultService.create(transport, {
      qrCapture: {
        sources: ['screen'],
        capture: async () => (await transport.invoke<string[] | null>('scan_screen_region')) ?? undefined,
      },
    });
    transport.on('scan_screen_region', () => {
      const next = results.shift();
      return next === undefined ? Promise.reject({ code: 'screenCaptureDenied', message: 'denied' }) : next;
    });
    expect(desktop.qrCapture?.sources).toEqual(['screen']);
    expect(await desktop.qrCapture!.capture('screen')).toEqual(['otpauth://totp/x?secret=JBSWY3DPEHPK3PXP']);
    expect(await desktop.qrCapture!.capture('screen')).toBeUndefined();
    const denied = await desktop.qrCapture!.capture('screen').catch((error: unknown) => error);
    expect(isVaultError(denied, 'screenCaptureDenied')).toBe(true);
  });

  it('offers sharing only where the Rust side has it, and follows its change events', async () => {
    const { service: phone } = await connect();
    expect(phone.sharing).toBeUndefined();

    const transport = new FakeTransport().on('session_snapshot', () => unlocked);
    const service = await TauriVaultService.create(transport, { sharing: true });
    const changes = vi.fn();
    const stop = service.sharing!.onSharingChange(changes);
    transport.emit('vault://sharing-changed', null);
    expect(changes).toHaveBeenCalledOnce();
    stop();
    transport.emit('vault://sharing-changed', null);
    expect(changes).toHaveBeenCalledOnce();
  });

  it('passes sharing calls to Rust in the shape the commands expect', async () => {
    const fingerprint = { digits: '0001 0002 0003 0004 0005 0006', emoji: [] };
    const account = { accountId: 'b', email: 'bob@example.com', publicEncKey: 'e', publicSignKey: 's', fingerprint };
    const transport = new FakeTransport()
      .on('session_snapshot', () => unlocked)
      .on('lookup_account', (args) => (args!.email === 'bob@example.com' ? account : Promise.reject({ code: 'accountNotFound', message: 'AccountNotFound' })))
      .on('add_member', () => undefined)
      .on('remove_member', (args) => (args!.accountId === 'b' ? undefined : Promise.reject({ code: 'notAllowed', message: 'NotAllowed' })))
      .on('emergency_action', () => undefined)
      .on('add_emergency_contact', () => ({ id: 'c1' }))
      .on('open_share_link', () => ({ overview: { schemaVersion: 1, type: 'login', title: 'Bank' }, details: { schemaVersion: 1 } }));
    const sharing = (await TauriVaultService.create(transport, { sharing: true })).sharing!;

    expect(await sharing.lookupAccount('bob@example.com')).toEqual(account);
    const missing = await sharing.lookupAccount('nobody@example.com').catch((error: unknown) => error);
    expect(isVaultError(missing, 'accountNotFound')).toBe(true);

    await sharing.addMember('v1', account, 'read');
    expect(transport.calls.at(-1)).toEqual({ command: 'add_member', args: { vaultId: 'v1', account, role: 'read' } });
    await sharing.removeMember('v1', 'b');
    const refused = await sharing.removeMember('v1', 'c').catch((error: unknown) => error);
    expect(isVaultError(refused, 'notAllowed')).toBe(true);

    await sharing.addEmergencyContact({ account, waitDays: 7, accessLevel: 'view', scope: { type: 'vault', vaultId: 'v1' } });
    expect(transport.calls.at(-1)?.args).toEqual({ account, waitDays: 7, accessLevel: 'view', scope: { type: 'vault', vaultId: 'v1' } });
    await sharing.requestEmergencyAccess('c1');
    expect(transport.calls.at(-1)?.args).toEqual({ id: 'c1', action: 'request' });
    await sharing.approveEmergencyAccess('c1');
    expect(transport.calls.at(-1)?.args).toEqual({ id: 'c1', action: 'approve' });

    await sharing.openShareLink('ct', 'key');
    expect(transport.calls.at(-1)?.args).toEqual({ ciphertext: 'ct', key: 'key', passphrase: null });
  });

  it('makes a share link\'s address for the web vault, since this page isn\'t on its origin', async () => {
    const created = { id: 'l1', key: 'k', expiresAt: '2026-10-26T00:00:00Z' };
    const hosted: SessionSnapshot = { ...unlocked, session: { ...unlocked.session, serverUrl: 'https://vault.octap.app' } };
    const transport = new FakeTransport().on('session_snapshot', () => hosted).on('create_share_link', () => created);
    const sharing = (await TauriVaultService.create(transport, { sharing: true })).sharing!;
    const link = await sharing.createShareLink('i1', { expiresInHours: 24, maxViews: 1, passphrase: '' });
    expect(link).toEqual({ ...created, url: 'https://vault.octap.app/s/l1#k' });
    expect(transport.calls.at(-1)?.args).toEqual({ itemId: 'i1', options: { expiresInHours: 24, maxViews: 1, passphrase: null } });
  });

  it('gives an emergency file the media type the opened item lists', async () => {
    const view = {
      contact: { id: 'c1' },
      vaults: [],
      items: [{ id: 'i1', vaultId: 'v', revision: 1, createdAt: '', updatedAt: '', overview: { schemaVersion: 1, type: 'document', title: 'Will' }, details: { schemaVersion: 1, attachments: [{ id: 'a1', name: 'will.pdf', type: 'application/pdf', size: 3, key: 'k' }] } }],
    };
    const transport = new FakeTransport()
      .on('session_snapshot', () => unlocked)
      .on('open_emergency_access', () => view)
      .on('emergency_attachment', () => new Uint8Array([1, 2, 3]).buffer)
      .on('lock', () => undefined);
    const service = await TauriVaultService.create(transport, { sharing: true });
    const sharing = service.sharing!;
    await sharing.openEmergencyAccess('c1');
    const file = await sharing.getEmergencyAttachment('c1', 'i1', 'a1');
    expect(file.type).toBe('application/pdf');
    expect(new Uint8Array(await file.arrayBuffer())).toEqual(new Uint8Array([1, 2, 3]));
    expect(transport.calls.at(-1)?.args).toEqual({ id: 'c1', itemId: 'i1', attachmentId: 'a1' });

    // Nothing about the grantor's items outlives the session.
    service.lock();
    expect((await sharing.getEmergencyAttachment('c1', 'i1', 'a1')).type).toBe('');
  });
});
