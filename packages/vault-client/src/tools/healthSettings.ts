// What the dashboard remembers: dismissed warnings and the opt-in email breach alerts. It lives in
// one hidden vault item, so it's encrypted like the rest of the vault, follows the account to its
// other devices, and dismissing a warning doesn't touch the login it's about (no new version of the
// login, no conflict with an edit elsewhere, and it works in vaults shared read-only).

import type { EmailBreach, EmailBreachResult, HealthCheck, Item, ItemDetails, VaultService } from '../types';
import { SCHEMA_VERSION } from '../types';

export const HEALTH_SETTINGS_TYPE = 'healthSettings' as const;
/** How often a device asks about email breaches by itself. "Check again" asks at once. */
export const EMAIL_BREACH_CHECK_HOURS = 24;
/** The most addresses one check sends. */
export const MAX_EMAIL_BREACH_ADDRESSES = 50;

export interface HealthSettingsDetails {
  schemaVersion: typeof SCHEMA_VERSION;
  /** Warning keys, from `warningKey`. */
  dismissed?: string[];
  emailBreachAlerts?: EmailBreachAlerts;
  /** Files never go here; this keeps `ItemDetails.attachments` readable on every type. */
  attachments?: never;
}

export interface EmailBreachAlerts {
  enabled: boolean;
  /**
   * The second opt-in: also look up the recovery map's other addresses (recovery emails and email
   * usernames that are neither the account email nor an alias). Off unless the user turns it on.
   */
  recoveryEmails?: boolean;
  checkedAt?: string;
  found?: EmailBreachResult[];
  /** Warning keys of the check before, so a report can mark what's new. Missing after the first. */
  previous?: string[];
}

/**
 * Names a warning for dismissing it. `version` is what the warning is about, so a new fact brings
 * it back: a dismissed weak password warns again once the password changes.
 */
export function warningKey(check: HealthCheck, subject: string, version = ''): string {
  return `${check}:${subject}:${version}`;
}

export type EmailBreachCheck = 'off' | 'notDue' | 'checked' | 'failed';

export const isHealthSettings = (item: Pick<Item, 'overview'>) => item.overview.type === HEALTH_SETTINGS_TYPE;

/**
 * Merges every live settings item. Two devices saving at once leave a conflict copy: dismissals are
 * a union, so neither is lost, and the alerts come from the newest save.
 */
export function readHealthSettings(items: Item[]): HealthSettingsDetails {
  const found = items.filter((item) => isHealthSettings(item) && !item.deletedAt).sort((a, b) => a.updatedAt.localeCompare(b.updatedAt));
  const merged: HealthSettingsDetails = { schemaVersion: SCHEMA_VERSION };
  const dismissed = new Set<string>();
  for (const item of found) {
    const details = item.details as HealthSettingsDetails;
    for (const key of details.dismissed ?? []) dismissed.add(key);
    if (details.emailBreachAlerts) merged.emailBreachAlerts = details.emailBreachAlerts;
  }
  if (dismissed.size > 0) merged.dismissed = [...dismissed];
  return merged;
}

export type HealthSettingsVault = Pick<VaultService, 'listItems' | 'getItem' | 'saveItem' | 'deleteItem' | 'listVaults' | 'lookupEmailBreaches'>;

export interface HealthSettings {
  read(): Promise<HealthSettingsDetails>;
  dismiss(warnings: string[]): Promise<void>;
  restore(warnings: string[]): Promise<void>;
  /** Turning alerts off forgets their results. */
  setEmailBreachAlerts(enabled: boolean): Promise<void>;
  /**
   * The second opt-in, while alerts are on. Either way the results are forgotten, so the next check
   * (which the caller runs at once) holds exactly the addresses the user now agreed to.
   */
  setRecoveryEmailChecks(enabled: boolean): Promise<void>;
  /**
   * Looks the addresses up, one at a time, when alerts are on and a day has passed (or `force`).
   * Results replace the last ones only when every address answered. A function gets the stored
   * alerts, so the addresses follow the opt-ins as they are now, not as an older report saw them.
   */
  checkEmailBreaches(addresses: string[] | ((alerts: EmailBreachAlerts) => string[]), options?: { force?: boolean; now?: Date }): Promise<EmailBreachCheck>;
}

export function createHealthSettings(vault: HealthSettingsVault): HealthSettings {
  // One save at a time: a second dismissal must start from the revision of the first.
  let queue: Promise<unknown> = Promise.resolve();
  const inOrder = <T>(work: () => Promise<T>): Promise<T> => {
    const run = queue.then(work, work);
    queue = run.catch(() => undefined);
    return run;
  };

  const stored = async (): Promise<Item[]> => {
    const summaries = await vault.listItems({ type: HEALTH_SETTINGS_TYPE });
    return Promise.all(summaries.map((summary) => vault.getItem(summary.id)));
  };

  const update = (change: (details: HealthSettingsDetails) => HealthSettingsDetails) =>
    inOrder(async () => {
      const items = await stored();
      const next = change(readHealthSettings(items));
      const [first, ...extras] = items.sort((a, b) => a.createdAt.localeCompare(b.createdAt) || a.id.localeCompare(b.id));
      const personal = first?.vaultId ?? (await vault.listVaults()).find((v) => v.type === 'personal')?.id;
      if (!personal) throw new Error('no personal vault');
      await vault.saveItem({
        ...(first ? { id: first.id, revision: first.revision } : {}),
        vaultId: personal,
        overview: first?.overview ?? { schemaVersion: SCHEMA_VERSION, type: HEALTH_SETTINGS_TYPE, title: 'Health settings' },
        details: next as ItemDetails,
      });
      await Promise.all(extras.map((extra) => vault.deleteItem(extra.id)));
    });

  return {
    read: async () => readHealthSettings(await stored()),

    dismiss: (warnings) => update((details) => ({ ...details, dismissed: [...new Set([...(details.dismissed ?? []), ...warnings])] })),

    restore: (warnings) => {
      const gone = new Set(warnings);
      return update((details) => ({ ...details, dismissed: (details.dismissed ?? []).filter((key) => !gone.has(key)) }));
    },

    setEmailBreachAlerts: (enabled) => update((details) => ({ ...details, emailBreachAlerts: { enabled } })),

    setRecoveryEmailChecks: (enabled) =>
      update((details) =>
        details.emailBreachAlerts?.enabled ? { ...details, emailBreachAlerts: { enabled: true, ...(enabled ? { recoveryEmails: true } : {}) } } : details,
      ),

    async checkEmailBreaches(addresses, { force = false, now = new Date() } = {}) {
      const alerts = readHealthSettings(await stored()).emailBreachAlerts;
      if (!alerts?.enabled) return 'off';
      const checkedAt = alerts.checkedAt ? Date.parse(alerts.checkedAt) : 0;
      if (!force && now.getTime() - checkedAt < EMAIL_BREACH_CHECK_HOURS * 3_600_000) return 'notDue';
      const found: EmailBreachResult[] = [];
      const list = typeof addresses === 'function' ? addresses(alerts) : addresses;
      try {
        for (const address of list.slice(0, MAX_EMAIL_BREACH_ADDRESSES)) {
          const breaches: EmailBreach[] = await vault.lookupEmailBreaches(address);
          if (breaches.length > 0) found.push({ address, breaches });
        }
      } catch {
        return 'failed';
      }
      await update((details) => {
        const current = details.emailBreachAlerts;
        // Turned off while the check ran, or the second opt-in changed: the change wins, and nothing found is kept.
        if (!current?.enabled || current.recoveryEmails !== alerts.recoveryEmails) return details;
        const previous = current.checkedAt
          ? (current.found ?? []).flatMap(({ address, breaches }) => breaches.map((b) => warningKey('emailBreach', address.toLowerCase(), b.name)))
          : undefined;
        return {
          ...details,
          emailBreachAlerts: { enabled: true, ...(current.recoveryEmails ? { recoveryEmails: true } : {}), checkedAt: now.toISOString(), found, ...(previous ? { previous } : {}) },
        };
      });
      return 'checked';
    },
  };
}
