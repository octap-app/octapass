import type { IconName } from '@octapass/ui';
import type { HealthCheck, HealthReport } from '@octapass/vault-client';
import type { MessageKey } from '../../i18n';

/** Each check's page is `/health/<slug>`. `recovery` isn't one: `/health/recovery` is the recovery map. */
export type CheckSlug =
  | 'weak'
  | 'reused'
  | 'breached'
  | 'two-step'
  | 'recovery-emails'
  | 'recovery-breached'
  | 'insecure'
  | 'old'
  | 'passkeys'
  | 'expiring'
  | 'backup-codes'
  | 'email-breaches';

export interface CheckInfo {
  slug: CheckSlug;
  icon: IconName;
  label: MessageKey;
  help: MessageKey;
  count: (report: HealthReport) => number;
  /** On the Health page even with nothing to fix. The others appear once they find something. */
  always?: boolean;
}

/** In the order the Health page lists them: what counts towards the score first. */
export const CHECKS: readonly CheckInfo[] = [
  { slug: 'weak', icon: 'alert', label: 'health.weak', help: 'health.weakHelp', count: (r) => r.weak.length, always: true },
  { slug: 'reused', icon: 'copy', label: 'health.reused', help: 'health.reusedHelp', count: (r) => r.reused.reduce((n, group) => n + group.length, 0), always: true },
  { slug: 'breached', icon: 'shield', label: 'health.breached', help: 'health.breachedHelp', count: (r) => r.breached.length, always: true },
  { slug: 'two-step', icon: 'clock', label: 'health.missing2fa', help: 'health.missing2faHelp', count: (r) => r.missing2fa.length, always: true },
  { slug: 'recovery-emails', icon: 'mail', label: 'health.recoveryNo2fa', help: 'health.recoveryNo2faHelp', count: (r) => r.recoveryNo2fa.length, always: true },
  // Found by email breach alerts, so it appears once they find something.
  { slug: 'recovery-breached', icon: 'alert', label: 'health.recoveryBreached', help: 'health.recoveryBreachedHelp', count: (r) => r.recoveryBreached.length },
  { slug: 'insecure', icon: 'lock', label: 'health.insecureUrls', help: 'health.insecureUrlsHelp', count: (r) => r.insecureUrls.length },
  { slug: 'old', icon: 'history', label: 'health.old', help: 'health.oldHelp', count: (r) => r.old.length },
  { slug: 'passkeys', icon: 'passkey', label: 'health.passkeyAvailable', help: 'health.passkeyAvailableHelp', count: (r) => r.passkeyAvailable.length },
  { slug: 'expiring', icon: 'card', label: 'health.expiring', help: 'health.expiringHelp', count: (r) => r.expiring.length },
  { slug: 'backup-codes', icon: 'key', label: 'health.backupCodes', help: 'health.backupCodesHelp', count: (r) => r.lowBackupCodes.length },
  { slug: 'email-breaches', icon: 'mail', label: 'health.email.title', help: 'health.email.help', count: (r) => r.emailBreaches.found.length },
];

export function findCheck(slug: string | undefined): CheckInfo | undefined {
  return CHECKS.find((check) => check.slug === slug);
}

/** What a dismissed warning was about, for the dismissed list. */
export const CHECK_LABELS: Record<HealthCheck, MessageKey> = {
  weak: 'health.weak',
  reused: 'health.reused',
  breached: 'health.breached',
  old: 'health.old',
  missing2fa: 'health.missing2fa',
  passkeyAvailable: 'health.passkeyAvailable',
  insecureUrl: 'health.insecureUrls',
  expiring: 'health.expiring',
  backupCodes: 'health.backupCodes',
  recoveryNo2fa: 'health.recoveryNo2fa',
  recoveryBreached: 'health.recoveryBreached',
  emailBreach: 'health.email.title',
};
