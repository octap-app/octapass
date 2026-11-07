import { PASSKEY_DOMAINS } from '../data/passkey-domains';
import { TWO_FACTOR_DOMAINS } from '../data/two-factor-domains';
import { itemDates } from '../items';
import type { CardDetails, EmailBreachFinding, HealthCheck, HealthEntry, HealthReport, Item, LoginDetails, StrengthEstimate } from '../types';
import { isHealthSettings, readHealthSettings, warningKey, type HealthSettingsDetails } from './healthSettings';
import { buildRecoveryMap, entryOf, hasTwoStep } from './recovery';
import { changePasswordUrl, hostnameOf, insecureUrl, registrableDomain } from './url';

const BREACH_CONCURRENCY = 4;
const WEAK_SCORE = 2;
// How much each problem scales an item's health; a breached password zeroes it.
const PENALTY = { veryWeak: 0.3, weak: 0.6, reused: 0.5, missing2fa: 0.85, insecureUrl: 0.85 };
const DAY_MS = 86_400_000;
/** A password this old is listed. A reminder, not a rule: a strong, unique password doesn't wear out. */
export const OLD_PASSWORD_DAYS = 365;
export const EXPIRY_WARNING_DAYS = 60;
export const LOW_BACKUP_CODES = 2;

function passwordOf(item: Item): string | undefined {
  if (item.overview.type !== 'login' && item.overview.type !== 'password') return undefined;
  return (item.details as LoginDetails).password || undefined;
}

function isOnSite(item: Item, sites: ReadonlySet<string>): boolean {
  return (item.overview.urls ?? []).some((url) => {
    const host = hostnameOf(url);
    return host !== undefined && sites.has(registrableDomain(host));
  });
}

function lacksSecondFactor(item: Item): boolean {
  return item.overview.type === 'login' && !hasTwoStep(item.details as LoginDetails) && isOnSite(item, TWO_FACTOR_DOMAINS);
}

function lacksPasskey(item: Item): boolean {
  return item.overview.type === 'login' && !(item.details as LoginDetails).passkeys?.length && isOnSite(item, PASSKEY_DOMAINS);
}

/**
 * When the password was last set: an imported date or the newest history entry, else when the item
 * was first saved. A plain edit of an item doesn't count, so `updatedAt` isn't used.
 */
function passwordDate(item: Item): string {
  const dates = itemDates(item);
  return dates.passwordChangedAt ?? dates.createdAt;
}

/** The same on every device, whichever way each one wrote the date. */
function passwordVersion(item: Item): string {
  const time = Date.parse(passwordDate(item));
  return Number.isNaN(time) ? '' : String(Math.floor(time / 1000));
}

/**
 * The last day an expiry date is valid, as `YYYY-MM-DD`. Reads `MM/YY` and `MM/YYYY` (the end of
 * that month, as on a card), `YYYY-MM` and `YYYY-MM-DD`.
 */
export function parseExpiry(text: string | undefined): string | undefined {
  const value = text?.trim() ?? '';
  const pad = (n: number, length = 2) => String(n).padStart(length, '0');
  const endOfMonth = (year: number, month: number) => `${pad(year, 4)}-${pad(month)}-${pad(new Date(Date.UTC(year, month, 0)).getUTCDate())}`;
  const monthYear = /^(\d{1,2})\s*[/-]\s*(\d{2}|\d{4})$/.exec(value);
  if (monthYear) {
    const month = Number(monthYear[1]);
    const year = Number(monthYear[2]);
    return month >= 1 && month <= 12 ? endOfMonth(year < 100 ? 2000 + year : year, month) : undefined;
  }
  const yearMonth = /^(\d{4})-(\d{2})$/.exec(value);
  if (yearMonth) {
    const month = Number(yearMonth[2]);
    return month >= 1 && month <= 12 ? endOfMonth(Number(yearMonth[1]), month) : undefined;
  }
  const date = /^(\d{4})-(\d{2})-(\d{2})/.exec(value);
  if (!date) return undefined;
  const [year, month, day] = [Number(date[1]), Number(date[2]), Number(date[3])];
  const parsed = new Date(Date.UTC(year, month - 1, day));
  return parsed.getUTCMonth() === month - 1 && parsed.getUTCDate() === day ? `${pad(year, 4)}-${pad(month)}-${pad(day)}` : undefined;
}

/** What the expiry check covers. `idDocument` is a passport, driver's licence or national ID. */
const EXPIRING_TYPES: ReadonlySet<string> = new Set(['card', 'idDocument']);

function expiryOf(item: Item): string | undefined {
  if (!EXPIRING_TYPES.has(item.overview.type)) return undefined;
  const details = item.details as CardDetails & { expiryDate?: unknown };
  for (const value of [details.expiry, details.expiryDate]) {
    const date = typeof value === 'string' ? parseExpiry(value) : undefined;
    if (date) return date;
  }
  return undefined;
}

async function mapLimited<T, R>(inputs: T[], limit: number, run: (input: T) => Promise<R>): Promise<R[]> {
  const results: R[] = new Array(inputs.length);
  let next = 0;
  const worker = async () => {
    while (next < inputs.length) {
      const index = next++;
      results[index] = await run(inputs[index]!);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, inputs.length) }, worker));
  return results;
}

/** Looks each unique password up once. Undefined when any lookup fails, so no partial result is shown. */
async function breachCounts(
  passwords: string[],
  checkBreached: (password: string) => Promise<number>,
): Promise<Map<string, number> | undefined> {
  try {
    const counts = await mapLimited(passwords, BREACH_CONCURRENCY, checkBreached);
    return new Map(passwords.map((password, i) => [password, counts[i]!]));
  } catch {
    return undefined;
  }
}

function emailBreachFindings(settings: HealthSettingsDetails): EmailBreachFinding[] {
  const alerts = settings.emailBreachAlerts;
  if (!alerts?.enabled) return [];
  const known = new Set(alerts.previous ?? []);
  return (alerts.found ?? []).flatMap(({ address, breaches }) =>
    breaches.map((breach) => {
      const warning = warningKey('emailBreach', address.toLowerCase(), breach.name);
      return { ...breach, address, warning, isNew: alerts.previous !== undefined && !known.has(warning) };
    }),
  );
}

/**
 * The caller passes items that are not in the trash. Dismissals and email breach results come from
 * the vault's health settings item when it's among them, or from `deps.settings`.
 */
export async function buildHealthReport(
  allItems: Item[],
  deps: { estimateStrength: (p: string) => StrengthEstimate; checkBreached: (p: string) => Promise<number>; settings?: HealthSettingsDetails },
  now: Date = new Date(),
): Promise<HealthReport> {
  const settings = deps.settings ?? readHealthSettings(allItems);
  const items = allItems.filter((item) => !isHealthSettings(item));
  const dismissedKeys = new Set(settings.dismissed ?? []);
  const dismissed: HealthReport['dismissed'] = [];
  const today = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());

  /** The entry for a warning, or nothing when the user dismissed it. */
  const warn = (item: Item, check: HealthCheck, version?: string): (HealthEntry & { warning: string }) | undefined => {
    const warning = warningKey(check, item.id, version);
    const entry = { ...entryOf(item), warning };
    if (!dismissedKeys.has(warning)) return entry;
    dismissed.push({ ...entry, check });
    return undefined;
  };
  const passwordWarning = (item: Item, check: HealthCheck) => {
    const entry = warn(item, check, passwordVersion(item));
    const url = entry && changePasswordUrl(item.overview.urls);
    return entry && url ? { ...entry, changePasswordUrl: url } : entry;
  };

  const checked = items.flatMap((item) => {
    const password = passwordOf(item);
    return password === undefined ? [] : [{ item, password }];
  });

  const byPassword = new Map<string, Item[]>();
  for (const { item, password } of checked) byPassword.set(password, [...(byPassword.get(password) ?? []), item]);

  const scores = new Map([...byPassword.keys()].map((password) => [password, deps.estimateStrength(password).score]));
  const counts = await breachCounts([...byPassword.keys()], deps.checkBreached);

  const weak = checked.flatMap(({ item, password }) => {
    const score = scores.get(password)!;
    const entry = score <= WEAK_SCORE ? passwordWarning(item, 'weak') : undefined;
    return entry ? [{ ...entry, score }] : [];
  });
  const breached = counts
    ? checked.flatMap(({ item, password }) => {
        const count = counts.get(password)!;
        const entry = count > 0 ? passwordWarning(item, 'breached') : undefined;
        return entry ? [{ ...entry, count }] : [];
      })
    : [];

  // A reused group is dismissed as a whole, and comes back whole when another login joins it.
  const reused: HealthEntry[][] = [];
  for (const group of [...byPassword.values()].filter((g) => g.length > 1).sort((a, b) => b.length - a.length)) {
    const keys = group.map((item) => warningKey('reused', item.id, passwordVersion(item)));
    if (keys.every((key) => dismissedKeys.has(key))) {
      for (const item of group) warn(item, 'reused', passwordVersion(item));
      continue;
    }
    keys.forEach((key) => dismissedKeys.delete(key));
    reused.push(group.map((item) => passwordWarning(item, 'reused')!));
  }

  const missing2fa = items.filter(lacksSecondFactor).flatMap((item) => warn(item, 'missing2fa') ?? []);
  const insecureUrls = items
    .filter((item) => item.overview.type === 'login')
    .flatMap((item) => {
      const url = insecureUrl(item.overview.urls);
      const entry = url === undefined ? undefined : warn(item, 'insecureUrl', url);
      return entry ? [{ ...entry, url: url! }] : [];
    });

  const has = (entries: HealthEntry[]) => new Set(entries.map((entry) => entry.itemId));
  const [weakIds, reusedIds, breachedIds, missingIds, insecureIds] = [weak, reused.flat(), breached, missing2fa, insecureUrls].map(has) as [
    Set<string>,
    Set<string>,
    Set<string>,
    Set<string>,
    Set<string>,
  ];

  let total = 0;
  for (const { item, password } of checked) {
    const score = scores.get(password)!;
    let health = breachedIds.has(item.id) ? 0 : 1;
    if (weakIds.has(item.id)) health *= score <= 1 ? PENALTY.veryWeak : PENALTY.weak;
    if (reusedIds.has(item.id)) health *= PENALTY.reused;
    if (missingIds.has(item.id)) health *= PENALTY.missing2fa;
    if (insecureIds.has(item.id)) health *= PENALTY.insecureUrl;
    total += health;
  }

  const old = checked
    .flatMap(({ item }) => {
      const changedAt = passwordDate(item);
      const ageDays = Math.floor((now.getTime() - Date.parse(changedAt)) / DAY_MS);
      const entry = ageDays >= OLD_PASSWORD_DAYS ? passwordWarning(item, 'old') : undefined;
      return entry ? [{ ...entry, changedAt, ageDays }] : [];
    })
    .sort((a, b) => b.ageDays - a.ageDays);

  const expiring = items
    .flatMap((item) => {
      const expiresOn = expiryOf(item);
      if (!expiresOn) return [];
      const daysLeft = Math.round((Date.parse(expiresOn) - today) / DAY_MS);
      const entry = daysLeft <= EXPIRY_WARNING_DAYS ? warn(item, 'expiring', expiresOn) : undefined;
      return entry ? [{ ...entry, expiresOn, daysLeft }] : [];
    })
    .sort((a, b) => a.daysLeft - b.daysLeft);

  const lowBackupCodes = items
    .filter((item) => item.overview.type === 'login')
    .flatMap((item) => {
      const codes = (item.details as LoginDetails).recovery?.backupCodes ?? [];
      const unused = codes.filter((code) => !code.used).length;
      const entry = codes.length > 0 && unused <= LOW_BACKUP_CODES ? warn(item, 'backupCodes', String(unused)) : undefined;
      return entry ? [{ ...entry, unused }] : [];
    });

  const { recovery, recoveryNo2fa } = buildRecoveryMap(items);
  const recoveryWarnings = recoveryNo2fa.flatMap((entry) => {
    const warning = warningKey('recoveryNo2fa', entry.itemId, entry.email.toLowerCase());
    if (!dismissedKeys.has(warning)) return [{ ...entry, warning }];
    dismissed.push({ ...entry, subtitle: entry.email, warning, check: 'recoveryNo2fa' });
    return [];
  });

  const emailFindings = emailBreachFindings(settings);
  for (const finding of emailFindings) {
    if (dismissedKeys.has(finding.warning)) dismissed.push({ itemId: '', vaultId: '', title: finding.title, subtitle: finding.address, warning: finding.warning, check: 'emailBreach' });
  }

  return {
    score: checked.length === 0 ? 100 : Math.round((total / checked.length) * 100),
    checked: checked.length,
    weak,
    reused,
    breached,
    breachCheckCompleted: counts !== undefined,
    missing2fa,
    recovery,
    recoveryNo2fa: recoveryWarnings,
    old,
    passkeyAvailable: items.filter(lacksPasskey).flatMap((item) => warn(item, 'passkeyAvailable') ?? []),
    insecureUrls,
    expiring,
    lowBackupCodes,
    emailBreaches: {
      enabled: settings.emailBreachAlerts?.enabled === true,
      ...(settings.emailBreachAlerts?.checkedAt ? { checkedAt: settings.emailBreachAlerts.checkedAt } : {}),
      found: emailFindings.filter((finding) => !dismissedKeys.has(finding.warning)),
    },
    dismissed,
    generatedAt: now.toISOString(),
  };
}

/** The account email and the masked email aliases the vault knows, each once. */
export function emailBreachAddresses(accountEmail: string | undefined, report: Pick<HealthReport, 'recovery'>): string[] {
  const aliases = report.recovery.filter((contact) => contact.kind === 'email' && contact.aliasProvider).map((contact) => contact.value);
  const seen = new Set<string>();
  return [...(accountEmail ? [accountEmail] : []), ...aliases].filter((address) => {
    const key = address.trim().toLowerCase();
    if (!key || seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/** The report without these warnings, until the next report: dismissing shows at once. */
export function withoutWarnings(report: HealthReport, warnings: ReadonlySet<string>): HealthReport {
  const keep = <T extends { warning?: string }>(entries: T[]) => entries.filter((entry) => !entry.warning || !warnings.has(entry.warning));
  return {
    ...report,
    weak: keep(report.weak),
    reused: report.reused.filter((group) => group.some((entry) => !entry.warning || !warnings.has(entry.warning))),
    breached: keep(report.breached),
    missing2fa: keep(report.missing2fa),
    recoveryNo2fa: keep(report.recoveryNo2fa),
    old: keep(report.old),
    passkeyAvailable: keep(report.passkeyAvailable),
    insecureUrls: keep(report.insecureUrls),
    expiring: keep(report.expiring),
    lowBackupCodes: keep(report.lowBackupCodes),
    emailBreaches: { ...report.emailBreaches, found: keep(report.emailBreaches.found) },
    dismissed: keep(report.dismissed),
  };
}
