// Import and export on the WASM core (crates/octapass-core `import` and `export`): every importer,
// the encrypted export with its attachments, and the FIDO Credential Exchange Format. The web
// vault's worker and the browser extension (account and local vaults) share it; each passes in how
// to read and save items and files.
//
// The encrypted export is written and read a piece at a time: one attachment's plaintext is in
// memory at once, and the file is read in slices, so a large vault never needs to fit twice.

import type * as CoreModule from '@octapass/core';
import type { ExistingLogin, ImportResult as CoreImportResult, ImportSource as CoreSource, ItemPlaintext, KdfParams } from '@octapass/core';
import { VaultError } from '../errors';
import { attachmentsOf } from '../items';
import type { Attachment, CodeLink, ExportFormat, ExportOptions, ImportOptions, ImportResult, ImportReview, ImportSource, Item, LoginDetails, QrScan, Vault } from '../types';
import { base64UrlEncode } from './encoding';
import { exportCsv, exportJson } from './export';

export type TransferCore = Pick<
  typeof CoreModule,
  'importFile' | 'ExportWriter' | 'ExportReader' | 'exportCxf' | 'isEncryptedExport' | 'relinkImportedItems' | 'linkImportedCodes' | 'readQrPixels' | 'summarizeQrScans'
> &
  QrImages;

/** The core's image decoders: in every build but the web vault's, which leaves them out for size. */
export interface QrImages {
  readQrImage?: (bytes: Uint8Array) => string[];
}

/** Images bigger than this are scaled down before reading, as the core would. */
const QR_MAX_SIDE = 2048;

/** Slices read from an import file. */
const SLICE = 1024 * 1024;

export interface ExportSource {
  vaults: Vault[];
  /** Live items (no trash). */
  items: Item[];
  /** Reads an attachment's file. Vaults without files leave it out. */
  readAttachment?: (item: Item, attachment: Attachment) => Promise<Blob>;
  /** CXF: whose export this is, and the exporting app's domain (the server's host). */
  account: { id: string; email: string };
  exporterRpId: string;
  now: Date;
  /** The encrypted export's Argon2id settings. Tests pass cheap ones; apps leave the core's default. */
  kdf?: KdfParams;
}

const TYPES: Record<ExportFormat, string> = {
  json: 'application/json',
  csv: 'text/csv',
  cxf: 'application/json',
  encrypted: 'application/octet-stream',
};

export async function exportVaultFile(core: TransferCore, format: ExportFormat, source: ExportSource, options: ExportOptions = {}): Promise<Blob> {
  const type = TYPES[format];
  switch (format) {
    case 'csv':
      return new Blob([exportCsv(source.vaults, source.items)], { type });
    case 'json':
      return new Blob([exportJson(source.vaults, source.items, source.now)], { type });
    case 'cxf': {
      const account = { id: source.account.id, username: '', email: source.account.email };
      const json = exportJson(source.vaults, source.items, source.now);
      return new Blob([core.exportCxf(json, account, source.exporterRpId, Math.floor(source.now.getTime() / 1000)).json], { type });
    }
    case 'encrypted':
      return exportEncrypted(core, source, options.password ?? '');
  }
}

async function exportEncrypted(core: TransferCore, source: ExportSource, password: string): Promise<Blob> {
  // The core refuses an empty password; the export screen asks for a long one first.
  const writer = new core.ExportWriter(password, source.kdf);
  try {
    // Finished pieces go into Blobs as they come, which the browser may keep on disk.
    const parts: BlobPart[] = [toBuffer(writer.addItems(exportJson(source.vaults, source.items, source.now)))];
    for (const item of source.items) {
      for (const attachment of attachmentsOf(item)) {
        if (attachment.pending || !source.readAttachment) continue;
        const file = await source.readAttachment(item, attachment);
        parts.push(new Blob([toBuffer(writer.addFile(attachment.id, new Uint8Array(await file.arrayBuffer())))]));
      }
    }
    parts.push(toBuffer(writer.finish()));
    return new Blob(parts, { type: TYPES.encrypted });
  } finally {
    writer.free();
  }
}

function toBuffer(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return bytes as Uint8Array<ArrayBuffer>;
}

/** Where an import goes. */
export interface ImportTarget {
  /** Logins already in the vault, so authenticator imports can add codes to them. */
  existingLogins: ExistingLogin[];
  /**
   * The live items already in the vaults, so importing a file again updates them (through
   * `updateItem`) instead of adding copies. Vaults without `updateItem` leave it out. Only the
   * target vault's (`vaultId`) are compared, except that an Octa Pass export also finds its own
   * items, by id, in every vault: it holds them all, and an import goes into one.
   */
  existingItems?: Item[];
  /** The vault the import goes into. Without it, every item in `existingItems` counts as in it. */
  vaultId?: string;
  /**
   * New item ids, so links between imported items can point at them before they're saved. Vaults
   * that pick their own ids leave it out and get `updateItem` calls for the links afterwards.
   */
  newId?: () => string;
  /**
   * Saves new items, under `id` when there is one. Returns each item's id as saved (`undefined` when
   * it wasn't), and a warning for each one that wasn't.
   */
  saveItems(entries: { id?: string; item: ItemPlaintext }[]): Promise<{ ids: (string | undefined)[]; warnings: string[] }>;
  /** Saves a new version of an item already in the vault (relinked items, and items a file imported again changed). */
  updateItem?: (id: string, item: ItemPlaintext) => Promise<void>;
  /** Sets the one-time code of a login already in the vault. */
  setTotp(itemId: string, totp: string): Promise<void>;
  /** Attaches a file to a saved item. Vaults that can't hold files leave it out. */
  attach?: (itemId: string, file: Blob, name: string) => Promise<void>;
}

/**
 * `fullCore` loads a build of the core with everything, for files this one can't read: the web
 * vault's size-optimised core has no OpenPGP, so a Proton Pass PGP-encrypted export is parsed by
 * the full core (loaded only then) and saved with this one.
 */
export async function importVaultFile(
  core: TransferCore,
  source: ImportSource,
  file: Blob,
  options: ImportOptions,
  target: ImportTarget,
  fullCore?: () => Promise<Pick<TransferCore, 'importFile'>>,
): Promise<ImportResult> {
  const vault = target.updateItem ? vaultOptions(target.existingItems, target.vaultId) : vaultOptions(undefined, undefined);
  if (source === 'octapass' && core.isEncryptedExport(new Uint8Array(await file.slice(0, 4).arrayBuffer()))) {
    return importEncrypted(core, file, options.password ?? '', target, vault);
  }
  const bytes = new Uint8Array(await file.arrayBuffer());
  const keyFile = options.keyFile ? base64UrlEncode(new Uint8Array(await options.keyFile.arrayBuffer())) : undefined;
  // Only fields that have a value: the core refuses `undefined` where it expects a list or text.
  const coreOptions = {
    ...(options.password !== undefined ? { password: options.password } : {}),
    ...(keyFile !== undefined ? { keyFile } : {}),
    existingLogins: target.existingLogins,
    ...vault,
  };
  const parse = (parser: Pick<TransferCore, 'importFile'>) => parser.importFile(source as CoreSource, bytes, coreOptions);
  let parsed: CoreImportResult;
  try {
    parsed = parse(core);
  } catch (error) {
    if ((error as { code?: unknown }).code !== 'pgp_unavailable' || !fullCore) throw importError(error);
    const full = await fullCore();
    parsed = run(() => parse(full));
  }
  const batch = new ImportBatch(core, target);
  await batch.addItems(parsed);
  return batch.finish();
}

/**
 * Authenticator imports waiting for the review. The parsed file (secrets included) stays here, in
 * the worker or the extension's service worker; the review screen only gets names.
 */
export class PendingImports {
  private readonly pending = new Map<string, CoreImportResult>();

  /**
   * `existingItems`: the target vault's items, so codes a backup brought in before are updated
   * (matched by the app's id) instead of added again.
   */
  async review(core: TransferCore, source: ImportSource, file: Blob, options: ImportOptions, existingLogins: ExistingLogin[], existingItems?: Item[], vaultId?: string): Promise<ImportReview> {
    const bytes = new Uint8Array(await file.arrayBuffer());
    // Missing options arrive as `null` from the JSON-shaped ports; leave out fields without a value.
    const parsed = run(() =>
      core.importFile(source as CoreSource, bytes, {
        ...(options?.password !== undefined ? { password: options.password } : {}),
        existingLogins,
        ...vaultOptions(existingItems, vaultId),
      }),
    );
    const id = crypto.randomUUID();
    this.pending.set(id, parsed);
    const codes = parsed.codes ?? [];
    const codeItems = codes.filter((code) => code.item !== undefined).length;
    return {
      id,
      codes: codes.map((code, index) => ({
        index,
        title: code.title,
        ...(code.issuer ? { issuer: code.issuer } : {}),
        ...(code.account ? { account: code.account } : {}),
        ...(code.update !== undefined ? { loginId: parsed.totpUpdates[code.update]!.itemId } : {}),
      })),
      otherItems: parsed.items.length - codeItems,
      skipped: parsed.skipped,
      warnings: parsed.warnings,
    };
  }

  async finish(core: TransferCore, id: string, links: CodeLink[], target: ImportTarget): Promise<ImportResult> {
    const parsed = this.pending.get(id);
    if (!parsed) throw new VaultError('importReviewExpired');
    this.pending.delete(id);
    const linked = core.linkImportedCodes(parsed, links);
    const batch = new ImportBatch(core, target);
    await batch.addItems(linked);
    return batch.finish();
  }

  cancel(id: string): void {
    this.pending.delete(id);
  }

  /** On lock and sign-out. */
  clear(): void {
    this.pending.clear();
  }
}

/**
 * The text of every QR code in an image. Without the core's decoders, the browser decodes the
 * image (any format it shows, HEIC and AVIF included) and the core reads the pixels.
 */
export async function readQrCodes(core: Pick<TransferCore, 'readQrPixels' | 'readQrImage'>, image: Blob): Promise<string[]> {
  if (core.readQrImage) {
    try {
      return core.readQrImage(new Uint8Array(await image.arrayBuffer()));
    } catch (error) {
      if ((error as { code?: unknown }).code === 'invalid_image') throw new VaultError('invalidImage', (error as Error).message);
      throw error;
    }
  }
  const { width, height, luma } = await browserPixels(image);
  return core.readQrPixels(width, height, luma);
}

/** Greyscale pixels, transparent ones over white, at most `QR_MAX_SIDE` on the longer side. */
async function browserPixels(image: Blob): Promise<{ width: number; height: number; luma: Uint8Array }> {
  let bitmap: ImageBitmap;
  try {
    bitmap = await createImageBitmap(image);
  } catch {
    throw new VaultError('invalidImage');
  }
  const scale = Math.min(1, QR_MAX_SIDE / Math.max(bitmap.width, bitmap.height));
  const width = Math.max(1, Math.round(bitmap.width * scale));
  const height = Math.max(1, Math.round(bitmap.height * scale));
  const canvas = new OffscreenCanvas(width, height);
  const context = canvas.getContext('2d', { willReadFrequently: true })!;
  context.fillStyle = '#fff';
  context.fillRect(0, 0, width, height);
  context.imageSmoothingQuality = 'high';
  context.drawImage(bitmap, 0, 0, width, height);
  bitmap.close();
  const rgba = context.getImageData(0, 0, width, height).data;
  const luma = new Uint8Array(width * height);
  for (let i = 0; i < luma.length; i++) luma[i] = (rgba[i * 4]! * 299 + rgba[i * 4 + 1]! * 587 + rgba[i * 4 + 2]! * 114) / 1000;
  return { width, height, luma };
}

export function summarizeQrScans(core: Pick<TransferCore, 'summarizeQrScans'>, texts: string[]): QrScan {
  return core.summarizeQrScans(texts);
}

/** Runs a core importer, turning its errors into the ones the import screen shows. */
export function run<T>(parse: () => T): T {
  try {
    return parse();
  } catch (error) {
    throw importError(error);
  }
}

export function importError(error: unknown): unknown {
  const code = (error as { code?: unknown }).code;
  const message = (error as Error).message;
  switch (code) {
    case 'import_password_required':
      return new VaultError('importPasswordRequired', message);
    case 'wrong_import_password':
      return new VaultError('wrongImportPassword', message);
    case 'invalid_import_file':
    case 'unsupported_import':
    case 'pgp_unavailable':
      return new VaultError('invalidImportFile', message);
    default:
      return error;
  }
}

/** The core's `existingItems`, `vaultId` and `now`: what an import compares the file with. */
function vaultOptions(items: Item[] | undefined, vaultId: string | undefined): Pick<CoreModule.ImportOptions, 'existingItems' | 'vaultId' | 'now'> {
  return {
    ...(items !== undefined ? { existingItems: items.map(({ id, vaultId, updatedAt, overview, details }) => ({ id, vaultId, updatedAt, overview, details }) as ItemPlaintext & { id: string; vaultId: string; updatedAt: string }) } : {}),
    ...(vaultId !== undefined ? { vaultId } : {}),
    now: new Date().toISOString(),
  };
}

async function importEncrypted(core: TransferCore, file: Blob, password: string, target: ImportTarget, vault: Pick<CoreModule.ImportOptions, 'existingItems' | 'vaultId' | 'now'>): Promise<ImportResult> {
  const reader = run(() => new core.ExportReader(password, vault));
  const batch = new ImportBatch(core, target);
  try {
    for (let offset = 0; offset < file.size; offset += SLICE) {
      const slice = new Uint8Array(await file.slice(offset, offset + SLICE).arrayBuffer());
      await batch.add(run(() => reader.push(slice)));
    }
    await batch.add(run(() => reader.finish()));
  } finally {
    reader.free();
  }
  return batch.finish();
}

/** Saves what an import produced: items first, then (encrypted exports) their files as they arrive. */
class ImportBatch {
  private imported = 0;
  private updated = 0;
  private unchanged = 0;
  private skipped = 0;
  private readonly warnings: string[] = [];
  /** Files still to come, by their id in the export: where they go. */
  private readonly files = new Map<string, { itemId: string; name: string; type: string }[]>();
  private filesKept = 0;
  private filesDropped = 0;

  constructor(
    private readonly core: TransferCore,
    private readonly target: ImportTarget,
  ) {}

  async add(entries: CoreModule.ExportEntry[]): Promise<void> {
    for (const entry of entries) {
      if (entry.kind === 'items') await this.addItems(entry.result);
      else await this.addFile(entry.fileId, entry.data);
    }
  }

  async addItems(parsed: CoreImportResult): Promise<void> {
    const { newId } = this.target;
    const linked = Boolean(parsed.sourceIds?.length);
    const chosen = newId ? parsed.items.map(() => newId()) : undefined;
    const items = chosen && linked ? this.core.relinkImportedItems(parsed.items, parsed.sourceIds!, chosen) : parsed.items;
    // An Octa Pass export imported again can point an item it updates at one it brings back.
    let updates = parsed.updates ?? [];
    const relinkUpdates = (ids: string[]) => {
      const relinked = this.core.relinkImportedItems(updates.map(({ item }) => item), parsed.sourceIds!, ids);
      updates = updates.map((update, i) => ({ ...update, item: relinked[i]! }));
    };
    if (chosen && linked && updates.length > 0) relinkUpdates(chosen);
    const { ids, warnings } = await this.target.saveItems(items.map((item, i) => ({ id: chosen?.[i], item })));
    const saved = ids.filter((id): id is string => id !== undefined).length;
    this.imported += saved;
    this.skipped += parsed.skipped + items.length - saved;
    this.warnings.push(...parsed.warnings, ...warnings);
    if (!chosen && linked && this.target.updateItem) {
      const placed = ids.map((id) => id ?? '');
      const relinked = this.core.relinkImportedItems(items, parsed.sourceIds!, placed);
      for (const [i, item] of relinked.entries()) {
        if (ids[i] && JSON.stringify(item) !== JSON.stringify(items[i])) await this.target.updateItem(ids[i]!, item);
      }
      if (updates.length > 0) relinkUpdates(placed);
    }
    for (const { itemId, item } of updates) {
      try {
        await this.target.updateItem!(itemId, item);
        this.updated++;
      } catch (error) {
        this.skipped++;
        this.warnings.push(`“${item.overview.title}” couldn’t be updated: ${(error as Error).message}`);
      }
    }
    this.unchanged += parsed.unchanged ?? 0;
    for (const { itemId, totp } of parsed.totpUpdates) {
      await this.target.setTotp(itemId, totp);
      this.imported++;
    }
    for (const file of parsed.files ?? []) {
      const itemId = ids[file.item];
      if (itemId) this.expect(file.fileId, { itemId, name: file.name, type: file.type });
    }
    // Files the vault's own copy of an item lacks (an Octa Pass export imported again).
    for (const file of parsed.existingFiles ?? []) this.expect(file.fileId, { itemId: file.itemId, name: file.name, type: file.type });
  }

  private expect(fileId: string, destination: { itemId: string; name: string; type: string }): void {
    const list = this.files.get(fileId) ?? [];
    list.push(destination);
    this.files.set(fileId, list);
  }

  private async addFile(fileId: string, data: Uint8Array): Promise<void> {
    const destinations = this.files.get(fileId) ?? [];
    this.files.delete(fileId);
    for (const { itemId, name, type } of destinations) {
      if (!this.target.attach) {
        this.filesDropped++;
        continue;
      }
      await this.target.attach(itemId, new Blob([data as Uint8Array<ArrayBuffer>], { type }), name);
      this.filesKept++;
    }
  }

  finish(): ImportResult {
    const missing = [...this.files.values()].reduce((sum, list) => sum + list.length, 0);
    if (missing > 0) this.warnings.push(`${missing} attached ${missing === 1 ? 'file is' : 'files are'} missing from the export file.`);
    if (this.filesDropped > 0) {
      this.warnings.push(`${this.filesDropped} attached ${this.filesDropped === 1 ? 'file wasn’t' : 'files weren’t'} imported: a vault on this device only can’t hold files.`);
    }
    const result: ImportResult = { imported: this.imported, skipped: this.skipped, warnings: this.warnings };
    if (this.updated > 0) result.updated = this.updated;
    if (this.unchanged > 0) result.unchanged = this.unchanged;
    if (this.filesKept > 0) result.files = this.filesKept;
    return result;
  }
}

/** The logins an authenticator import may add codes to. */
export function existingLogins(items: Item[]): ExistingLogin[] {
  return items
    .filter((item) => !item.deletedAt && (item.overview.type === 'login' || item.overview.type === 'password'))
    .map((item) => {
      const details = item.details as LoginDetails;
      // Only fields that have a value: the core refuses `undefined` where it expects a list or text.
      return {
        id: item.id,
        title: item.overview.title,
        urls: item.overview.urls ?? [],
        ...(details.username ? { username: details.username } : {}),
        ...(item.overview.subtitle ? { subtitle: item.overview.subtitle } : {}),
        hasTotp: Boolean(details.totp),
        // So importing an authenticator backup again doesn't add the codes the vault already has.
        ...(details.totp ? { totp: details.totp } : {}),
      };
    });
}
