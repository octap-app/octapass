// The key log (plan 03, "Key transparency"): publishing this account's keys, checking other
// people's before sealing to them, and watching the log for keys nobody here made. The checks
// themselves are in the core; this file fetches, and keeps what the core pins on this device.

import type * as CoreModule from '@octapass/core';
import type { AccountBundle, KeyLog, KeyRecord, Session } from '@octapass/core';
import { VaultError } from '../errors';
import { normalizeEmail } from '../items';
import type { KeyLogCheck, KeyLogState } from '../types';
import type { Api } from './api';
import { ApiProblem } from './http';
import type { LocalStore } from './store';

export type KeyLogCore = Pick<typeof CoreModule, 'KeyLog' | 'keyLogBlind' | 'keyLogFinishLabel'>;

/** A device reads the log at most this often. */
const MONITOR_EVERY_MS = 60 * 60 * 1000;

export interface KeyLogHost {
  core(): Promise<KeyLogCore>;
  session(): Session;
  api(): Api;
  account(): AccountBundle;
  /** Keeps the bundle with the account's ML-KEM key and record, here and in storage. */
  setAccount(account: AccountBundle): Promise<void>;
  accountId(): string;
  store: LocalStore;
  now(): number;
  /** The key log's state changed: an alert, or a finished check. */
  changed(): void;
}

/** The keys to check, as a lookup or a member list gives them. */
export interface OfferedAccount {
  accountId: string;
  email: string;
  publicEncKey: string;
  publicSignKey: string;
  keyRecord?: KeyRecord;
}

/** A server from before the key log, or a request this account has no budget left for. */
function isUnavailable(error: unknown): boolean {
  return error instanceof ApiProblem ? error.status === 404 || error.status === 429 : false;
}

export class KeyLogEngine {
  private queue: Promise<unknown> = Promise.resolve();

  constructor(private readonly host: KeyLogHost) {}

  /** One at a time, against the stored pins, which are saved after a failure too: a failed check is how an alert gets recorded. */
  private withLog<T>(task: (log: KeyLog) => Promise<T>): Promise<T> {
    const run = async () => {
      const core = await this.host.core();
      const accountId = this.host.accountId();
      const log = new core.KeyLog((await this.host.store.keyLog(accountId)) ?? undefined);
      try {
        return await task(log);
      } finally {
        await this.host.store.setKeyLog(accountId, log.save());
        log.free();
      }
    };
    const result = this.queue.then(run, run);
    this.queue = result.catch(() => undefined);
    return result;
  }

  private async pinHead(log: KeyLog): Promise<void> {
    if (log.oprfKey) return;
    log.acceptHead(await this.host.api().keyLogHead(0));
  }

  private async label(log: KeyLog, email: string): Promise<string> {
    const normalized = normalizeEmail(email);
    const known = log.knownLabel(normalized);
    if (known) return known;
    const core = await this.host.core();
    await this.pinHead(log);
    const { state, blinded } = core.keyLogBlind(normalized);
    const { evaluated, proof } = await this.host.api().keyLogLabel(blinded);
    const label = core.keyLogFinishLabel(normalized, state, evaluated, proof, log.oprfKey!);
    log.rememberLabel(normalized, label);
    return label;
  }

  /**
   * Makes sure the session has the account's ML-KEM key and the account has a record in the log,
   * before the sync that may bring hybrid grants. Another device may have published already; its
   * record comes with the account. Returns whether the session gained the ML-KEM key.
   */
  async ensurePublished(): Promise<boolean> {
    const session = this.host.session();
    if (this.host.account().keyRecord) return false;
    const fresh = await this.host.api().getAccount();
    if (fresh.keyRecord && fresh.wrappedPqPrivateKey) {
      await this.adopt(session, { record: fresh.keyRecord, wrappedPqPrivateKey: fresh.wrappedPqPrivateKey });
      return true;
    }
    await this.withLog((log) => this.publish(log));
    return true;
  }

  private async publish(log: KeyLog): Promise<void> {
    const session = this.host.session();
    await this.pinHead(log);
    const keys = session.prepareKeyRecord(log.logId!, await this.label(log, this.host.account().email));
    await this.host.api().publishKeys(keys);
    await this.adopt(session, keys);
  }

  private async adopt(session: Session, keys: { record: KeyRecord; wrappedPqPrivateKey: string }): Promise<void> {
    session.adoptKeyRecord(keys);
    await this.host.setAccount({ ...this.host.account(), keyRecord: keys.record, wrappedPqPrivateKey: keys.wrappedPqPrivateKey });
  }

  /**
   * Checks this account's record and reads what's new in the log, at most hourly. Never throws for what it finds: the alert is how that shows.
   * `stillOpen`: run in the background, it stops asking the server once the vault it started for is locked or closed. A request then
   * would have no access token, and refreshing one in the background could end a session the user is signing in to again.
   */
  async monitor(options: { force?: boolean; stillOpen?: () => boolean } = {}): Promise<void> {
    const record = this.host.account().keyRecord;
    if (!record) return;
    const open = options.stillOpen ?? (() => true);
    const unchanged = await this.withLog(async (log) => {
      if (!options.force && this.host.now() - log.checkedAt < MONITOR_EVERY_MS) return true;
      const before = Boolean(log.alert);
      try {
        if (!open()) return true;
        log.checkOwn(record, await this.host.api().keyLogProof(record.label, log.pinnedSize));
        for (let range = log.scanRange(); range && open(); range = log.scanRange()) {
          log.applyPage(await this.host.api().keyLogEntries(range[0]!, range[1]!));
        }
      } catch (error) {
        if (!isUnavailable(error) && !isCoreMismatch(error)) throw error;
      }
      return before === Boolean(log.alert);
    });
    if (!unchanged) this.host.changed();
  }

  /** Checks keys the server offered, on this device. `failed` means don't seal to them. */
  async check(account: OfferedAccount): Promise<KeyLogCheck> {
    return this.withLog(async (log) => {
      try {
        const label = await this.label(log, account.email);
        const proof = await this.host.api().keyLogProof(label, log.pinnedSize);
        return log.verifyAccount(account, label, proof) ? 'verified' : 'notLogged';
      } catch (error) {
        if (isCoreMismatch(error)) return 'failed';
        if (error instanceof ApiProblem) return 'unavailable';
        throw error;
      }
    });
  }

  /** As `check`, for when a key is about to be sealed. */
  async require(account: OfferedAccount): Promise<void> {
    if ((await this.check(account)) === 'failed') throw new VaultError('keyLogMismatch');
  }

  async state(): Promise<KeyLogState> {
    const { keyRecord } = this.host.account();
    return this.withLog(async (log) => {
      const { alert, checkedAt } = log;
      return {
        published: Boolean(keyRecord),
        ...(checkedAt ? { checkedAt: new Date(checkedAt).toISOString() } : {}),
        ...(alert ? { alert: { kind: alert.kind, at: new Date(alert.at).toISOString() } } : {}),
      };
    });
  }

  async dismissAlert(): Promise<void> {
    await this.withLog(async (log) => {
      log.reset();
      await this.pinHead(log);
      // A log that started again has no record of this account. The ML-KEM key stays.
      const { keyRecord } = this.host.account();
      if (keyRecord && keyRecord.logId !== log.logId) await this.publish(log);
    });
    this.host.changed();
    await this.monitor({ force: true });
  }
}

function isCoreMismatch(error: unknown): boolean {
  return typeof error === 'object' && error !== null && 'code' in error && (error as { code: unknown }).code === 'key_log_mismatch';
}
