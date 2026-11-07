// "Use on this device only" (plan 01, Local mode): a vault with no account, stored encrypted in
// this browser's IndexedDB. It answers the same calls as the account engine, so the popup's
// screens work unchanged; calls that need a server say so.
//
// A local vault can't be wrapped for a service worker restart the way an account session can
// (the core has no such call for it), so the service worker stays awake while one is unlocked.

import type * as Full from '@octapass/core/full';
import {
  buildHealthReport,
  compareSummaries,
  createBreachChecker,
  estimateStrength,
  existingLogins,
  exportVaultFile,
  isHotp,
  loginDetails,
  storeEquivalentDomains,
  importVaultFile,
  matchesFilter,
  PendingImports,
  readQrCodes,
  summarizeQrScans,
  summarizeItem,
  VaultError,
  withPasswordHistory,
  type AccountSummary,
  type CodeLink,
  type EquivalentDomains,
  type EquivalentDomainsDetails,
  type HotpCode,
  type ImportTarget,
  type ExportFormat,
  type ExportOptions,
  type HealthReport,
  type ImportOptions,
  type ImportResult,
  type ImportReview,
  type ImportSource,
  type Item,
  type ItemDraft,
  type ItemFilter,
  type ItemSummary,
  type LoginDetails,
  type TotpCode,
  type Vault,
  withConfirmed,
} from '@octapass/vault-client';
import { LOCAL_SERVER, type LocalMeta } from '../shared/local';

type LocalChip = NonNullable<LocalMeta['chip']>;
import type { ChipSecretWrap } from './desktop';
import type { KeyValueStore } from './storage';
import type { EngineEvent, Snapshot } from './vault';

export { LOCAL_SERVER };
export const LOCAL_NAME = 'This device';

const BLOB = 'local-vault';
const META = 'local-vault-meta';
/** Argon2id memory for new local vaults: 256 MiB where the browser allows it, else 64 MiB (plan 03). */
const MEMORY_KIB = [262_144, 65_536];

export interface LocalEngineOptions {
  loadCore: () => Promise<typeof Full>;
  disk: KeyValueStore;
  emit: (event: EngineEvent) => void;
  now?: () => number;
  /** Argon2id memory to try for new vaults, for tests. */
  memoryKib?: number[];
  /** The desktop app's chip, when it's installed (plan 05). */
  chip?: (vaultId: string, context?: string) => Promise<ChipSecretWrap | undefined>;
}

const iso = (ms: number) => new Date(ms).toISOString();

/** Core errors the screens know how to say. */
function normalize(error: unknown): unknown {
  const code = (error as { code?: unknown }).code;
  if (code === 'login_failed') return new VaultError('invalidCredentials');
  if (code === 'weak_master_password') return new Error('weak_master_password');
  return error;
}

export class LocalEngine {
  private vault: Full.LocalVault | undefined;
  private readonly imports = new PendingImports();
  private items = new Map<string, Item>();
  private stored = false;
  private readonly checkBreached = createBreachChecker();

  constructor(private readonly options: LocalEngineOptions) {}

  private now(): number {
    return this.options.now?.() ?? Date.now();
  }

  /** Whether this browser holds a local vault. */
  async init(): Promise<Snapshot> {
    this.stored = (await this.options.disk.get(BLOB)) !== undefined;
    return this.snapshot();
  }

  get exists(): boolean {
    return this.stored;
  }

  get unlocked(): boolean {
    return this.vault !== undefined;
  }

  snapshot(): Snapshot {
    if (!this.stored) return { session: { status: 'signedOut' }, remembered: [] };
    // Only the master password opens a local vault, and it never outlives the worker: an open one
    // was the user's own check (`SessionState.confirmed`).
    return { session: withConfirmed({ status: this.vault ? 'unlocked' : 'locked', email: LOCAL_NAME, serverUrl: LOCAL_SERVER }, this.vault !== undefined), remembered: [] };
  }

  // ---------- Creating, opening and closing ----------

  /** A new local vault, unlocked. Returns the backup recovery code for the local Recovery Kit. */
  async create(password: string): Promise<string> {
    if (this.stored) throw new VaultError('serverError', 'This browser already has a vault.');
    const core = await this.options.loadCore();
    const { chip, hardwareSecret } = await this.newChip(core);
    let vault: Full.LocalVault | undefined;
    const choices = this.options.memoryKib ?? MEMORY_KIB;
    for (const memoryKib of choices) {
      try {
        vault = core.LocalVault.create(password, { memoryKib, ...(hardwareSecret ? { hardwareSecret } : {}) });
        break;
      } catch (error) {
        // Out of memory for 256 MiB: try 64 MiB. Anything else (a weak password) is final.
        if ((error as { code?: unknown }).code === 'weak_master_password' || memoryKib === choices.at(-1)) throw normalize(error);
      }
    }
    await this.options.disk.set(META, { createdAt: iso(this.now()), ...(chip ? { chip } : {}) } satisfies LocalMeta);
    await this.open(vault!);
    return vault!.backupRecoveryCode;
  }

  /** Restores a `.octapass-backup` file as this browser's local vault, unlocked. */
  async restore(file: Uint8Array, secret: Full.BackupSecret, password: string): Promise<void> {
    if (this.stored) throw new VaultError('serverError', 'This browser already has a vault.');
    const core = await this.options.loadCore();
    const { chip, hardwareSecret } = await this.newChip(core);
    let vault: Full.LocalVault;
    try {
      vault = core.LocalVault.restoreBackup(file, secret, password, hardwareSecret ? { hardwareSecret } : undefined);
    } catch (error) {
      const code = (error as { code?: unknown }).code;
      if (code === 'invalid_backup' || code === 'login_failed' || code === 'invalid_recovery_code') throw new VaultError('invalidImportFile', String(code));
      throw normalize(error);
    }
    await this.options.disk.set(META, { createdAt: iso(this.now()), lastBackupAt: iso(this.now()), ...(chip ? { chip } : {}) } satisfies LocalMeta);
    await this.open(vault);
  }

  async unlock(password: string): Promise<void> {
    const blob = await this.options.disk.get<Uint8Array>(BLOB);
    if (!blob) throw new VaultError('locked');
    const core = await this.options.loadCore();
    const hardwareSecret = await this.storedChip(core);
    try {
      await this.open(core.LocalVault.unlock(blob, password, hardwareSecret));
    } catch (error) {
      throw normalize(error);
    }
  }

  /** A chip key in the desktop app for a new vault, when there's an app and it has a chip. */
  private async newChip(core: typeof Full): Promise<{ chip?: LocalChip; hardwareSecret?: Uint8Array }> {
    if (!this.options.chip) return {};
    const vaultId = crypto.randomUUID();
    let wrap: ChipSecretWrap | undefined;
    try {
      wrap = await this.options.chip(vaultId);
    } catch {
      return {}; // No app here: the vault relies on its strong master password (plan 03).
    }
    if (!wrap) return {};
    return { chip: { vaultId, context: wrap.context }, hardwareSecret: core.openChipSecret(wrap.key, wrap.sealedSecret) };
  }

  /** The secret of a vault bound to the app's chip. Throws when the app can't be reached: nothing else opens it. */
  private async storedChip(core: typeof Full): Promise<Uint8Array | undefined> {
    const chip = (await this.meta())?.chip;
    if (!chip) return undefined;
    const wrap = await this.options.chip?.(chip.vaultId, chip.context);
    if (!wrap) throw new VaultError('deviceUnlockUnsupported', 'appNotRunning');
    return core.openChipSecret(wrap.key, wrap.sealedSecret);
  }

  /** Opens the stored vault again with `password` and drops it: the export's master password check. */
  private async checkPassword(password: string): Promise<void> {
    const blob = await this.options.disk.get<Uint8Array>(BLOB);
    if (!blob) throw new VaultError('locked');
    const core = await this.options.loadCore();
    const hardwareSecret = await this.storedChip(core);
    try {
      core.LocalVault.unlock(blob, password, hardwareSecret).free();
    } catch (error) {
      throw normalize(error);
    }
  }

  lock(): void {
    if (!this.vault) return;
    this.imports.clear();
    this.vault.free();
    this.vault = undefined;
    this.items.clear();
    this.emitSession();
  }

  /** Removes the local vault from this browser, after it moved to an account. */
  async forget(): Promise<void> {
    this.vault?.free();
    this.vault = undefined;
    this.items.clear();
    await this.options.disk.delete(BLOB);
    await this.options.disk.delete(META);
    this.stored = false;
  }

  // ---------- Backups and turning on sync ----------

  async meta(): Promise<LocalMeta | undefined> {
    return this.options.disk.get<LocalMeta>(META);
  }

  async backup(): Promise<Blob> {
    const vault = this.require();
    const file = vault.createBackup();
    const meta = await this.meta();
    await this.options.disk.set(META, { ...meta, createdAt: meta?.createdAt ?? iso(this.now()), lastBackupAt: iso(this.now()) } satisfies LocalMeta);
    return new Blob([file as Uint8Array<ArrayBuffer>], { type: 'application/octet-stream' });
  }

  recoveryCode(): string {
    return this.require().backupRecoveryCode;
  }

  /** A `Signup` that keeps this vault's keys and items (`LocalVault.upgradeToAccount`). */
  upgrade(email: string, password: string): Full.Signup {
    return this.require().upgradeToAccount(email, password);
  }

  /** Every item as stored, for the first upload. */
  storedItems(): Full.LocalItem[] {
    return this.require().items();
  }

  // ---------- The engine calls ----------

  /** Answers a page's engine call, like the account engine would. */
  async call(method: string, args: unknown[]): Promise<unknown> {
    switch (method) {
      case 'init':
        return this.snapshot();
      case 'preload':
        await this.options.loadCore();
        return;
      case 'lock':
        return this.lock();
      case 'unlock':
        return this.unlock(args[0] as string);
      case 'confirmMasterPassword':
        // Reveal/copy/export on a local vault: reopening the stored vault is the check.
        return this.checkPassword(args[0] as string);
      case 'sync':
        return;
      case 'deviceUnlockStatus':
        return { enabled: false, passwordRequired: false };
      case 'getAccountSummary':
        return this.accountSummary();
      case 'listVaults':
        return this.vaults();
      case 'listItems':
        return this.listItems(args[0] as ItemFilter | undefined);
      case 'getItem':
        return this.getItem(args[0] as string);
      case 'saveItem':
        return this.saveItem(args[0] as ItemDraft);
      case 'deleteItem':
        return this.change(args[0] as string, (vault, id) => vault.deleteItem(id));
      case 'restoreItem':
        return this.change(args[0] as string, (vault, id) => vault.restoreItem(id));
      case 'totpCode':
        return this.totpCode(args[0] as string, args[1] as number | undefined);
      case 'itemVersions':
        // Version history lives on the sync server; a vault on this device only has none.
        return [];
      case 'nextHotpCode':
        return this.nextHotpCode(args[0] as string);
      case 'setHotpCounter':
        return this.setHotpCounter(args[0] as string, args[1] as number);
      case 'equivalentDomains':
        return this.equivalentDomains();
      case 'saveEquivalentDomains':
        return this.saveEquivalentDomains(args[0] as { groups: string[][]; excludedDefaults: string[] });
      case 'generatePasswordForSite':
        return (await this.options.loadCore()).generateForSite(args[0] as string, undefined, args[1] as Full.RandomGeneratorOptions);
      case 'checkBreached':
        return this.checkBreached(args[0] as string);
      case 'getHealthReport':
        return this.healthReport();
      case 'lookupEmailBreaches':
        // A local vault has no server to ask, and its address would have nowhere else to go.
        throw new VaultError('notFound');
      case 'exportVault':
        return this.exportVault(args[0] as ExportFormat, args[1] as ExportOptions | undefined);
      case 'importFile':
        return this.importFile(args[0] as ImportSource, args[1] as Blob, args[2] as ImportOptions | undefined);
      case 'reviewImport':
        return this.reviewImport(args[0] as ImportSource, args[1] as Blob, args[2] as ImportOptions | undefined);
      case 'finishImport':
        return this.finishImport(args[0] as string, args[1] as CodeLink[]);
      case 'cancelImport':
        return this.imports.cancel(args[0] as string);
      case 'readQrCodes':
        return readQrCodes(await this.options.loadCore(), args[0] as Blob);
      case 'summarizeQrScans':
        return summarizeQrScans(await this.options.loadCore(), args[0] as string[]);
      // The save inbox (plan 03, Saving while locked): its owner is this vault's id.
      case 'pinInbox':
        return this.require().inboxPin(args[0] as string);
      case 'openInbox':
        return this.require().inboxOpen(args[0] as string);
      case 'enableDeviceUnlock':
      case 'unlockWithDevice':
      case 'deviceUnlockCredential':
        throw new VaultError('deviceUnlockUnsupported');
      default:
        // Sign-in, account deletion, the Secret Key…: they need an account. Turn on sync first.
        throw new VaultError('serverError', 'This needs sync. Turn on sync in Settings first.');
    }
  }

  getItem(id: string): Item {
    this.require();
    const item = this.items.get(id);
    if (!item) throw new VaultError('notFound');
    return structuredClone(item);
  }

  listItems(filter?: ItemFilter): ItemSummary[] {
    this.require();
    return [...this.items.values()].map(summarizeItem).filter((s) => matchesFilter(s, filter)).sort(compareSummaries);
  }

  private require(): Full.LocalVault {
    if (!this.vault) throw new VaultError('locked');
    return this.vault;
  }

  private vaults(): Vault[] {
    return [{ id: this.require().vaultId, name: 'Personal', type: 'personal', role: 'owner' }];
  }

  private async open(vault: Full.LocalVault): Promise<void> {
    this.vault?.free();
    this.vault = vault;
    this.reindex();
    await this.persist();
    this.stored = true;
    this.emitSession();
  }

  /** Decrypts every item once: the popup lists and searches them while the vault is open. */
  private reindex(): void {
    const vault = this.require();
    this.items = new Map(
      vault.list().map((entry) => {
        const { overview, details } = vault.getItem(entry.id);
        const item = {
          id: entry.id,
          vaultId: vault.vaultId,
          revision: entry.updatedAt,
          createdAt: iso(entry.createdAt),
          updatedAt: iso(entry.updatedAt),
          ...(entry.deletedAt !== undefined ? { deletedAt: iso(entry.deletedAt) } : {}),
          overview,
          details,
        } as Item;
        return [entry.id, item];
      }),
    );
  }

  private async persist(): Promise<void> {
    await this.options.disk.set(BLOB, this.require().toBytes());
  }

  private async saveItem(draft: ItemDraft): Promise<Item> {
    const vault = this.require();
    const plaintext = (d: Pick<ItemDraft, 'overview' | 'details'>) => ({ overview: d.overview, details: d.details }) as unknown as Full.ItemPlaintext;
    let id: string;
    if (draft.id) {
      const existing = this.getItem(draft.id);
      id = draft.id;
      vault.updateItem(id, plaintext(withPasswordHistory(existing, draft, new Date(this.now()))));
    } else {
      id = vault.addItem(plaintext(draft));
    }
    await this.afterChange();
    return this.getItem(id);
  }

  private async change(id: string, fn: (vault: Full.LocalVault, id: string) => void): Promise<void> {
    this.getItem(id);
    fn(this.require(), id);
    await this.afterChange();
  }

  private async afterChange(): Promise<void> {
    this.reindex();
    await this.persist();
    this.options.emit({ type: 'items' });
  }

  private emitSession(): void {
    this.options.emit({ type: 'session', snapshot: this.snapshot() });
  }

  private accountSummary(): AccountSummary {
    return { email: LOCAL_NAME, itemCount: this.listItems().length, vaultCount: 1, deviceCount: 1, sharedVaultsOwned: [] };
  }

  private async updateTotp(id: string, change: (totp: string) => string): Promise<Item> {
    const item = this.getItem(id);
    const login = loginDetails(item);
    if (!login?.totp || !isHotp(login.totp)) throw new VaultError('notFound');
    return this.saveItem({ ...item, details: { ...login, totp: change(login.totp) } });
  }

  private async nextHotpCode(id: string): Promise<HotpCode> {
    const core = await this.options.loadCore();
    let code: HotpCode | undefined;
    await this.updateTotp(id, (totp) => {
      const next = core.nextHotpCode(totp);
      code = { code: next.code, counter: next.counter };
      return next.totp;
    });
    return code!;
  }

  private async setHotpCounter(id: string, counter: number): Promise<Item> {
    const core = await this.options.loadCore();
    return this.updateTotp(id, (totp) => core.withHotpCounter(totp, counter));
  }

  private async equivalentDomains(): Promise<EquivalentDomains> {
    const core = await this.options.loadCore();
    const settings = [...this.items.values()].filter((item) => item.overview.type === 'equivalentDomains' && !item.deletedAt).map((item) => item.details as EquivalentDomainsDetails).map(({ groups, excludedDefaults }) => ({ groups, ...(excludedDefaults && { excludedDefaults }) }));
    const options = core.equivalentMatchOptions(settings);
    return { groups: options.equivalentDomains ?? [], excludedDefaults: options.excludedDefaults ?? [], defaults: core.defaultEquivalentDomains() };
  }

  private async saveEquivalentDomains(input: { groups: string[][]; excludedDefaults: string[] }): Promise<EquivalentDomains & { rejected: string[] }> {
    const { groups, rejected } = (await this.options.loadCore()).cleanEquivalentGroups(input.groups);
    await storeEquivalentDomains(
      {
        items: async () => [...this.items.values()],
        vaults: async () => this.vaults(),
        save: (draft) => this.saveItem(draft),
        trash: (id) => this.change(id, (vault, itemId) => vault.deleteItem(itemId)),
      },
      { groups, excludedDefaults: input.excludedDefaults },
    );
    return { ...(await this.equivalentDomains()), rejected };
  }

  private async totpCode(totp: string, at?: number): Promise<TotpCode> {
    const core = await this.options.loadCore();
    return core.totpCode(totp, Math.floor((at ?? this.now()) / 1000));
  }

  private healthReport(): Promise<HealthReport> {
    const items = [...this.items.values()].filter((i) => !i.deletedAt);
    return buildHealthReport(items, { estimateStrength: (p) => estimateStrength(p), checkBreached: (p) => this.checkBreached(p) });
  }

  /** A local vault has no attachments and no account: its CXF export names the device's vault. */
  private async exportVault(format: ExportFormat, options?: ExportOptions): Promise<Blob> {
    if (options?.masterPassword !== undefined) await this.checkPassword(options.masterPassword);
    const vault = this.require();
    const items = [...this.items.values()].filter((i) => !i.deletedAt);
    return exportVaultFile(await this.options.loadCore(), format, { vaults: this.vaults(), items, account: { id: vault.vaultId, email: '' }, exporterRpId: 'octapass.local', now: new Date() }, options);
  }

  /** Files from an encrypted export can't be kept here: the import says how many were left out. */
  private async importFile(source: ImportSource, file: Blob, options: ImportOptions = {}): Promise<ImportResult> {
    const result = await importVaultFile(await this.options.loadCore(), source, file, options, this.importTarget());
    await this.afterChange();
    return result;
  }

  private async reviewImport(source: ImportSource, file: Blob, options: ImportOptions = {}): Promise<ImportReview> {
    this.require();
    const items = [...this.items.values()];
    return this.imports.review(await this.options.loadCore(), source, file, options, existingLogins(items), items.filter((i) => !i.deletedAt));
  }

  private async finishImport(reviewId: string, links: CodeLink[]): Promise<ImportResult> {
    const result = await this.imports.finish(await this.options.loadCore(), reviewId, links, this.importTarget());
    await this.afterChange();
    return result;
  }

  private importTarget(): ImportTarget {
    const vault = this.require();
    return {
      existingLogins: existingLogins([...this.items.values()]),
      existingItems: [...this.items.values()].filter((i) => !i.deletedAt),
      saveItems: async (entries) => ({ ids: entries.map(({ item }) => vault.addItem(item)), warnings: [] }),
      updateItem: async (id, item) => vault.updateItem(id, item),
      setTotp: async (itemId, totp) => {
        const item = this.getItem(itemId);
        vault.updateItem(itemId, { overview: item.overview, details: { ...(item.details as LoginDetails), totp } } as unknown as Full.ItemPlaintext);
      },
    };
  }
}
