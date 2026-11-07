import { Button, Icon, Ring, Spinner, type IconName } from '@octapass/ui';
import { isLocalServer, type HealthReport } from '@octapass/vault-client';
import { Link } from 'react-router';
import { useSession } from '../../app/ServiceContext';
import { Alert } from '../../components/Alert';
import { formatDate, t, type MessageKey } from '../../i18n';
import { errorMessage } from '../../lib/errors';
import { useHealth } from '../../lib/health';
import { useLocalVaults } from '../local/useLocalVaults';
import { PageHeader } from '../PageHeader';
import { CHECKS } from './checks';
import { useEmailChecksAvailable } from './EmailBreachSection';
import styles from './HealthPage.module.css';

/** A local vault's health includes its backups (plan 05). */
function LocalBackupLine() {
  const session = useSession();
  const { current } = useLocalVaults();
  if (!isLocalServer(session.serverUrl) || !current) return null;
  const line = current.lastBackupAt ? t('localVault.lastBackupHealth', { date: formatDate(current.lastBackupAt) }) : t('localVault.neverBackedUp');
  return <Alert tone={current.backupDue ? 'warn' : 'info'}>{line}</Alert>;
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
      <LocalBackupLine />

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
