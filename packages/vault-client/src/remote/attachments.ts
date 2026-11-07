// Attachments: files encrypted here, a piece at a time, under a key of their own that the item key
// wraps (crates/octapass-core `attachment`). The server stores ciphertext; the file's name, type,
// size and wrapped key live in the item's encrypted details.

import type * as CoreModule from '@octapass/core';
import type { Session } from '@octapass/core';
import { VaultError } from '../errors';
import { attachmentsOf } from '../items';
import type { Attachment, Item, StorageUsage } from '../types';
import type { Api } from './api';
import { ApiProblem } from './http';
import type { VaultIndex } from './vaultIndex';

export type AttachmentCore = Pick<typeof CoreModule, 'newId' | 'attachmentEncryptedSize'>;

export interface AttachmentHost {
  core(): Promise<AttachmentCore>;
  unlocked(): { session: Session; index: VaultIndex };
  api(): Api;
  /** Throws unless the vault takes writes from this account. */
  writable(vaultId: string): void;
  /** Rewrites the item's attachment list on top of the server's current version. */
  updateAttachments(itemId: string, change: (list: Attachment[]) => Attachment[]): Promise<Item>;
}

/** Plaintext read per step: big enough to keep the WASM calls few, small enough for any device. */
const SLICE = 1024 * 1024;

export class Attachments {
  constructor(private readonly host: AttachmentHost) {}

  async add(itemId: string, file: Blob, name: string): Promise<Item> {
    const { session, index } = this.host.unlocked();
    const entry = index.get(itemId);
    if (!entry || entry.record.deletedAt) throw new VaultError('notFound');
    const { vaultId, encryptedItemKey } = entry.record;
    this.host.writable(vaultId);

    const core = await this.host.core();
    const api = this.host.api();
    const stored = core.attachmentEncryptedSize(file.size);
    const usage = await api.usage();
    if (stored > usage.maxFileBytes) throw new VaultError('fileTooLarge');
    // The quota is the vault owner's, so only our own vaults can be checked here.
    if (index.vault(vaultId)?.role === 'owner' && usage.attachmentBytes + stored > usage.maxAttachmentBytes) {
      throw new VaultError('quotaExceeded');
    }

    const id = core.newId();
    const encryptor = session.newAttachment(vaultId, itemId, encryptedItemKey, id);
    const parts: Uint8Array<ArrayBuffer>[] = [];
    let key: string;
    try {
      for (let offset = 0; offset < file.size; offset += SLICE) {
        const plaintext = new Uint8Array(await file.slice(offset, offset + SLICE).arrayBuffer());
        parts.push(encryptor.push(plaintext) as Uint8Array<ArrayBuffer>);
      }
      parts.push(encryptor.finish() as Uint8Array<ArrayBuffer>);
      key = encryptor.wrappedKey;
    } finally {
      encryptor.free();
    }
    await api.uploadAttachment(vaultId, itemId, id, new Blob(parts));

    const attachment: Attachment = { id, name: name || 'file', type: file.type, size: file.size, key };
    try {
      return await this.host.updateAttachments(itemId, (list) => [...list, attachment]);
    } catch (error) {
      // Not listed anywhere, so nothing could ever open it: take it back off the server.
      void api.deleteAttachment(vaultId, itemId, id).catch(() => undefined);
      throw error;
    }
  }

  async get(itemId: string, attachmentId: string): Promise<Blob> {
    const { session, index } = this.host.unlocked();
    const entry = index.get(itemId);
    const attachment = entry && attachmentsOf(entry.item).find((a) => a.id === attachmentId);
    if (!entry || !attachment) throw new VaultError('notFound');
    const { vaultId, encryptedItemKey } = entry.record;

    const response = await this.host.api().downloadAttachment(vaultId, itemId, attachmentId);
    return decryptAttachment(session, { vaultId, itemId, encryptedItemKey }, attachment, response);
  }

  async remove(itemId: string, attachmentId: string): Promise<Item> {
    const { index } = this.host.unlocked();
    const entry = index.get(itemId);
    if (!entry || !attachmentsOf(entry.item).some((a) => a.id === attachmentId)) throw new VaultError('notFound');
    const { vaultId } = entry.record;
    this.host.writable(vaultId);
    // Unlisted first: a file left on the server only costs space, a listed file that's gone is broken.
    const item = await this.host.updateAttachments(itemId, (list) => list.filter((a) => a.id !== attachmentId));
    await this.host
      .api()
      .deleteAttachment(vaultId, itemId, attachmentId)
      .catch((error: unknown) => {
        if (!(error instanceof ApiProblem && error.status === 404)) throw error;
      });
    return item;
  }

  /** Copies every file of `fromItemId` onto `toItemId` (another vault's copy of it). */
  async copyAll(fromItemId: string, toItemId: string): Promise<Item | undefined> {
    const from = this.host.unlocked().index.get(fromItemId);
    let copied: Item | undefined;
    for (const attachment of from ? attachmentsOf(from.item) : []) {
      const file = await this.get(fromItemId, attachment.id);
      copied = await this.add(toItemId, file, attachment.name);
    }
    return copied;
  }

  async usage(): Promise<StorageUsage> {
    const { attachmentBytes, maxAttachmentBytes, maxFileBytes } = await this.host.api().usage();
    return { attachmentBytes, maxAttachmentBytes, maxFileBytes };
  }
}

/** Decrypts a downloaded file as it streams in. Its `type` is the attachment's media type. */
export async function decryptAttachment(
  session: Session,
  item: { vaultId: string; itemId: string; encryptedItemKey: string },
  attachment: Attachment,
  response: Response,
): Promise<Blob> {
  const decryptor = session.openAttachment(item.vaultId, item.itemId, item.encryptedItemKey, attachment.id, attachment.key);
  const parts: Uint8Array<ArrayBuffer>[] = [];
  try {
    const reader = response.body!.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      const plaintext = decryptor.push(value);
      if (plaintext.length) parts.push(plaintext as Uint8Array<ArrayBuffer>);
    }
    parts.push(decryptor.finish() as Uint8Array<ArrayBuffer>);
  } catch (error) {
    // A file that doesn't decrypt was changed or cut short on the way: never hand out part of it.
    if (error instanceof Error && error.name === 'OctaPassError') throw new VaultError('serverError', 'The file could not be decrypted.');
    throw error;
  } finally {
    decryptor.free();
  }
  return new Blob(parts, { type: attachment.type });
}
