import { Button, Icon, Ring, Spinner, type IconName } from '@octapass/ui';
import { isLocalServer, type HealthReport } from '@octapass/vault-client';
import { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router';
import { useService, useSession } from '../../app/ServiceContext';
import { Alert } from '../../components/Alert';
import { formatDate, t, type MessageKey } from '../../i18n';
import { errorMessage } from '../../lib/errors';
import { useHealth } from '../../lib/health';
import { daysSince, useLocalVaults } from '../local/useLocalVaults';
import { PageHeader } from '../PageHeader';
import { CHECKS } from './checks';
import { useEmailChecksAvailable } from './EmailBreachSection';
import styles from './HealthPage.module.css';

/** A local vault with no backup for this long gets the reminder (plan 01). */
export const BACKUP_REMINDER_DAYS = 30;

interface BackupStatus {
  lastBackupAt?: string;
  due: boolean;
  folder?: string;
}

/**
 * The open local vault's backups: from `service.local` (desktop) or `localBackupInfo` (the
 * extension). Undefined for an account, whose server holds its copy.
 */
function useBackupStatus(): BackupStatus | undefined {
  const service = useService();
  const session = useSession();
  const { current } = useLocalVaults();
  const [info, setInfo] = useState<{ createdAt?: string; lastBackupAt?: string }>();
  const local = isLocalServer(session.serverUrl);
  useEffect(() => {
    if (!local || service.local || !service.localBackupInfo) return;
    let live = true;
    service.localBackupInfo().then(
      (next) => live && setInfo(next),
      () => undefined,
    );
    return () => {
      live = false;
    };
  }, [service, local]);
  if (!local) return undefined;
  if (service.local) return current && { lastBackupAt: current.lastBackupAt, due: current.backupDue, folder: current.backupFolder };
  if (!info) return undefined;
  const since = info.lastBackupAt ?? info.createdAt;
  return { lastBackupAt: info.lastBackupAt, due: since !== undefined && daysSince(since) >= BACKUP_REMINDER_DAYS };
}

/** Plan 05: "Last backup 34 days ago", and a way to back up when one is due. Nothing leaves the device. */
function BackupReminder() {
  const status = useBackupStatus();
  const navigate = useNavigate();
  if (!status) return null;
  const days = status.lastBackupAt ? daysSince(status.lastBackupAt) : undefined;
  const line = days === undefined ? t('health.backup.never') : days <= 0 ? t('health.backup.today') : t('health.backup.daysAgo', { count: days });
  return (
    <Alert
      tone={status.due ? 'warn' : 'info'}
      action={
        <Button variant="ghost" size="sm" onClick={() => navigate('/settings#local')}>
          {t('health.backup.action')}
        </Button>
      }
    >
      <span data-testid="health-backup">
        {line}
        {status.folder ? ` · ${t('health.backup.automatic', { folder: status.folder })}` : ''}
        {status.due ? ` ${t('health.backup.due')}` : ''}
      </span>
    </Alert>
  );
}

function verdict(score: number): MessageKey {
  return score >= 90 ? 'health.verdict.great' : score >= 70 ? 'health.verdict.good' : score >= 50 ? 'health.verdict.fair' : 'health.verdict.poor';
}

/** The score and one tile per check. Each tile opens that check's list (`HealthCheckPage`). */
export function HealthPage() {
  const { report, loading, error, refresh } = useHealth();

  return (
    <div className={styles.page}>
      <PageHeader
        title={t('health.title')}
        subtitle={t('health.subtitle')}
        actions={
          <Button variant="secondary" size="sm" icon="refresh" busy={loading && Boolean(report)} onClick={refresh}>
            {t('health.recheck')}
          </Button>
        }
      />
      <div className={styles.body}>
        {error && !report ? (
          <Alert>{errorMessage(error)}</Alert>
        ) : !report ? (
          <div className={styles.loading} aria-busy="true">
            <Spinner size={28} />
            <p>{t('health.checking')}</p>
          </div>
        ) : (
          <Overview report={report} />
        )}
      </div>
    </div>
  );
}

interface Tile {
  slug: string;
  icon: IconName;
  label: MessageKey;
  value: number | string;
  clear: boolean;
}

function Overview({ report }: { report: HealthReport }) {
  const emailChecks = useEmailChecksAvailable();
  const tiles: Tile[] = CHECKS.flatMap((check): Tile[] => {
    const count = check.count(report);
    if (check.slug === 'email-breaches') {
      // The tile leads to the switch, so it's here whenever the switch would be.
      const { enabled } = report.emailBreaches;
      if (!enabled && !emailChecks && count === 0) return [];
      return [{ slug: check.slug, icon: check.icon, label: check.label, value: enabled ? count : t('health.email.offTile'), clear: enabled && count === 0 }];
    }
    if (!check.always && count === 0) return [];
    return [{ slug: check.slug, icon: check.icon, label: check.label, value: count, clear: count === 0 }];
  });

  return (
    <>
      <section className={styles.hero} aria-labelledby="score-title">
        <Ring value={report.score / 100} size={168} stroke={3.2} tone="gradient" className={styles.ring}>
          <span className={styles.score}>
            <b>{report.score}</b>
            <small>{t('health.outOf')}</small>
          </span>
        </Ring>
        <div className={styles.heroText}>
          <h2 id="score-title" className={styles.verdict}>
            {t(verdict(report.score))}
          </h2>
          <p>{t('health.summary', { count: report.checked })}</p>
          <p className={styles.checkedAt}>{t('health.checkedAt', { date: formatDate(report.generatedAt, 'long') })}</p>
        </div>
      </section>

      {!report.breachCheckCompleted && <Alert tone="warn">{t('health.breachUnavailable')}</Alert>}
      {report.emailBreaches.found.some((finding) => finding.isNew) && <Alert tone="warn">{t('health.email.newAlert')}</Alert>}
      <BackupReminder />

      <nav aria-label={t('health.checks')}>
        <ul className={styles.stats}>
          {tiles.map((tile) => (
            <li key={tile.slug}>
              <Link to={`/health/${tile.slug}`} className={styles.stat} data-clear={tile.clear || undefined} data-off={typeof tile.value === 'string' || undefined}>
                <Icon name={tile.clear ? 'check' : tile.icon} size={20} />
                <b>{tile.value}</b>
                <span>{t(tile.label)}</span>
                <Icon name="chevronRight" size={16} className={styles.statChev} />
              </Link>
            </li>
          ))}
        </ul>
      </nav>

      <ul className={styles.rows}>
        <li>
          <Link to="/health/recovery" className={styles.row}>
            <Icon name="lifebuoy" size={20} className={styles.rowIcon} />
            <span className={styles.rowText}>
              <b>{t('health.recoveryMap')}</b>
              <small>{t('health.recoveryMapSummary', { count: report.recovery.length })}</small>
            </span>
            <Icon name="chevronRight" size={16} className={styles.chev} />
          </Link>
        </li>
        {report.dismissed.length > 0 && (
          <li>
            <Link to="/health/dismissed" className={styles.row}>
              <Icon name="eyeOff" size={20} className={styles.rowIcon} />
              <span className={styles.rowText}>
                <b>{t('health.dismissedCount', { count: report.dismissed.length })}</b>
                <small>{t('health.dismissedNote')}</small>
              </span>
              <Icon name="chevronRight" size={16} className={styles.chev} />
            </Link>
          </li>
        )}
      </ul>
    </>
  );
}
