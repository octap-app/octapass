import { Avatar, Button, Icon, Spinner, useToast } from '@octapass/ui';
import type { HealthEntry, HealthReport } from '@octapass/vault-client';
import { useState, type ReactNode } from 'react';
import { Link, Navigate, useNavigate, useParams } from 'react-router';
import { Alert } from '../../components/Alert';
import { strengthLabel } from '../../components/StrengthHint';
import { formatDate, t } from '../../i18n';
import { errorMessage } from '../../lib/errors';
import { useHealth } from '../../lib/health';
import { PageHeader } from '../PageHeader';
import { ChangePasswordDialog } from './ChangePasswordDialog';
import { CHECK_LABELS, findCheck, type CheckSlug } from './checks';
import { EmailBreachSection } from './EmailBreachSection';
import { Row } from './HealthRow';
import styles from './HealthPage.module.css';

const DISMISSED = 'dismissed';

/** One check's list (`/health/<slug>`), or the dismissed warnings (`/health/dismissed`), opened from the Health page. */
export function HealthCheckPage() {
  const { check: slug } = useParams();
  const { report, error } = useHealth();
  const navigate = useNavigate();
  const check = findCheck(slug);
  if (!check && slug !== DISMISSED) return <Navigate to="/health" replace />;

  const title = check ? t(check.label) : t('health.dismissedTitle');
  return (
    <div className={styles.page}>
      <PageHeader
        title={title}
        subtitle={check ? <Help slug={check.slug} report={report} /> : t('health.dismissedHelp')}
        actions={
          <Button variant="secondary" size="sm" icon="chevronLeft" onClick={() => navigate('/health')}>
            {t('nav.health')}
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
        ) : check ? (
          <CheckList slug={check.slug} label={title} report={report} />
        ) : (
          <DismissedList label={title} report={report} />
        )}
      </div>
    </div>
  );
}

function Help({ slug, report }: { slug: CheckSlug; report: HealthReport | undefined }) {
  const check = findCheck(slug)!;
  if (slug === 'breached')
    return (
      <>
        {t('health.breachedHelp')}{' '}
        <a href="https://octap.app/docs/security/breach-checks/" target="_blank" rel="noopener noreferrer">
          {t('health.howBreachWorks')}
        </a>
      </>
    );
  if (slug === 'recovery-emails')
    return (
      <>
        {t('health.recoveryNo2faHelp')} {report && t('health.recoveryMapSummary', { count: report.recovery.length })}{' '}
        <Link to="/health/recovery">{t('health.viewRecoveryMap')}</Link>
      </>
    );
  return t(check.help);
}

/** A check's rows, or "None found." once there's nothing left to fix. */
function List({ label, empty, children }: { label: string; empty: boolean; children: ReactNode }) {
  return empty ? (
    <p className={styles.clear}>
      <Icon name="check" size={18} />
      {t('health.noneFound')}
    </p>
  ) : (
    <ul className={styles.rows} aria-label={label}>
      {children}
    </ul>
  );
}

function CheckList({ slug, label, report }: { slug: CheckSlug; label: string; report: HealthReport }) {
  const { dismiss } = useHealth();
  const toast = useToast();
  const [changing, setChanging] = useState<HealthEntry>();
  const onDismiss = (warnings: (string | undefined)[]) => {
    const keys = warnings.filter((warning): warning is string => warning !== undefined);
    dismiss(keys).catch((e: unknown) => toast({ message: errorMessage(e), tone: 'danger' }));
  };
  const rowActions = (entry: HealthEntry) => ({ onChange: () => setChanging(entry), onDismiss: () => onDismiss([entry.warning]) });
  const dismissOnly = (entry: HealthEntry) => ({ onDismiss: () => onDismiss([entry.warning]) });

  const list = (() => {
    switch (slug) {
      case 'weak':
        return (
          <List label={label} empty={report.weak.length === 0}>
            {report.weak.map((e) => (
              <Row key={e.itemId} entry={e} tag={strengthLabel(e.score)} tone="danger" {...rowActions(e)} />
            ))}
          </List>
        );
      case 'reused':
        return (
          <List label={label} empty={report.reused.length === 0}>
            {report.reused.map((group, i) => (
              <li key={i} className={styles.reuseGroup}>
                <div className={styles.reuseHead}>
                  <p className={styles.reuseTitle}>{t('health.reuseGroup', { count: group.length })}</p>
                  <Button variant="ghost" size="sm" onClick={() => onDismiss(group.map((e) => e.warning))}>
                    {t('health.dismissGroup')}
                  </Button>
                </div>
                <ul className={styles.rows}>
                  {group.map((e) => (
                    <Row key={e.itemId} entry={e} onChange={() => setChanging(e)} />
                  ))}
                </ul>
              </li>
            ))}
          </List>
        );
      case 'breached':
        return (
          <>
            {!report.breachCheckCompleted && <Alert tone="warn">{t('health.breachUnavailable')}</Alert>}
            {(report.breachCheckCompleted || report.breached.length > 0) && (
              <List label={label} empty={report.breached.length === 0}>
                {report.breached.map((e) => (
                  <Row key={e.itemId} entry={e} tag={t('health.seenTimes', { count: e.count })} tone="danger" {...rowActions(e)} />
                ))}
              </List>
            )}
          </>
        );
      case 'two-step':
        return (
          <List label={label} empty={report.missing2fa.length === 0}>
            {report.missing2fa.map((e) => (
              <Row key={e.itemId} entry={e} tag={t('health.supports2fa')} tone="warn" {...dismissOnly(e)} />
            ))}
          </List>
        );
      case 'recovery-emails':
        return (
          <List label={label} empty={report.recoveryNo2fa.length === 0}>
            {report.recoveryNo2fa.map((e) => (
              <Row key={e.itemId} entry={{ ...e, subtitle: e.email }} tag={t('health.recoveryResets', { count: e.accounts })} tone="warn" {...dismissOnly(e)} />
            ))}
          </List>
        );
      case 'recovery-breached':
        return (
          <List label={label} empty={report.recoveryBreached.length === 0}>
            {report.recoveryBreached.map((e) => (
              <Row
                key={e.email}
                entry={{ ...e, subtitle: `${e.email} · ${t('health.recoveryBreachedIn', { breaches: e.breaches.join(', ') })}` }}
                tag={t('health.recoveryResets', { count: e.accounts })}
                tone="danger"
                {...dismissOnly(e)}
              />
            ))}
          </List>
        );
      case 'insecure':
        return (
          <List label={label} empty={report.insecureUrls.length === 0}>
            {report.insecureUrls.map((e) => (
              <Row key={e.itemId} entry={{ ...e, subtitle: e.url }} tag="http://" tone="warn" {...dismissOnly(e)} />
            ))}
          </List>
        );
      case 'old':
        return (
          <List label={label} empty={report.old.length === 0}>
            {report.old.map((e) => (
              <Row key={e.itemId} entry={e} tag={t('health.changedOn', { date: formatDate(e.changedAt) })} {...rowActions(e)} />
            ))}
          </List>
        );
      case 'passkeys':
        return (
          <List label={label} empty={report.passkeyAvailable.length === 0}>
            {report.passkeyAvailable.map((e) => (
              <Row key={e.itemId} entry={e} tag={t('health.supportsPasskeys')} {...dismissOnly(e)} />
            ))}
          </List>
        );
      case 'expiring':
        return (
          <List label={label} empty={report.expiring.length === 0}>
            {report.expiring.map((e) => (
              <Row
                key={e.itemId}
                entry={e}
                tag={e.daysLeft < 0 ? t('health.expired') : e.daysLeft === 0 ? t('health.expiresToday') : t('health.expiresIn', { count: e.daysLeft })}
                tone={e.daysLeft < 0 ? 'danger' : 'warn'}
                {...dismissOnly(e)}
              />
            ))}
          </List>
        );
      case 'backup-codes':
        return (
          <List label={label} empty={report.lowBackupCodes.length === 0}>
            {report.lowBackupCodes.map((e) => (
              <Row key={e.itemId} entry={e} tag={t('health.codesLeft', { count: e.unused })} tone="warn" {...dismissOnly(e)} />
            ))}
          </List>
        );
      case 'email-breaches':
        return <EmailBreachSection report={report} />;
    }
  })();

  return (
    <>
      {list}
      {changing && <ChangePasswordDialog entry={changing} onClose={() => setChanging(undefined)} />}
    </>
  );
}

/** Warnings the user dismissed. They don't count towards the score until shown again. */
function DismissedList({ label, report }: { label: string; report: HealthReport }) {
  const { restore } = useHealth();
  const toast = useToast();
  return (
    <List label={label} empty={report.dismissed.length === 0}>
      {report.dismissed.map((e) => (
        <li key={e.warning} className={styles.rowLine}>
          <div className={styles.row}>
            <Avatar name={e.title} size="sm" />
            <span className={styles.rowText}>
              <b>{e.title}</b>
              <small>{t(CHECK_LABELS[e.check])}</small>
            </span>
          </div>
          <div className={styles.rowActions}>
            <Button variant="ghost" size="sm" onClick={() => restore([e.warning]).catch((error: unknown) => toast({ message: errorMessage(error), tone: 'danger' }))}>
              {t('health.restore')}
            </Button>
          </div>
        </li>
      ))}
    </List>
  );
}
