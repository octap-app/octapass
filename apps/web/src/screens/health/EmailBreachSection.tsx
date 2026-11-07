import { Avatar, Button, Dialog, Switch, useToast } from '@octapass/ui';
import type { EmailBreachFinding, HealthReport } from '@octapass/vault-client';
import { useEffect, useState } from 'react';
import { useService, useSession } from '../../app/ServiceContext';
import { Alert } from '../../components/Alert';
import { formatDate, t } from '../../i18n';
import { errorMessage } from '../../lib/errors';
import { useHealth } from '../../lib/health';
import styles from './HealthPage.module.css';

const HIBP = 'https://haveibeenpwned.com';

/** Whether this account's server can check addresses, or undefined while it's asked. Local vaults have no server to ask. */
export function useEmailChecksAvailable(): boolean | undefined {
  const service = useService();
  const { serverUrl } = useSession();
  const [answer, setAnswer] = useState<{ serverUrl: string; available: boolean }>();
  useEffect(() => {
    if (!serverUrl) return;
    let current = true;
    service.getServerInfo(serverUrl).then(
      (info) => current && setAnswer({ serverUrl, available: info.emailBreachChecks === true }),
      () => current && setAnswer({ serverUrl, available: false }),
    );
    return () => {
      current = false;
    };
  }, [service, serverUrl]);
  if (!serverUrl) return false;
  return answer?.serverUrl === serverUrl ? answer.available : undefined;
}

/**
 * The email breach alerts page's body. Off by default. Turning it on sends addresses off the device,
 * so it asks first and says so.
 */
export function EmailBreachSection({ report }: { report: HealthReport }) {
  const { settings, refresh, emailCheck, checkEmails, dismiss } = useHealth();
  const toast = useToast();
  const available = useEmailChecksAvailable();
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const { enabled, checkedAt, found } = report.emailBreaches;
  if (!enabled && !available) return available === false ? <Alert tone="info">{t('health.email.unavailable')}</Alert> : null;

  const change = async (on: boolean) => {
    setBusy(true);
    try {
      await settings.setEmailBreachAlerts(on);
      setConfirming(false);
      if (on) await checkEmails(true);
      refresh();
    } catch (e) {
      toast({ message: errorMessage(e), tone: 'danger' });
    } finally {
      setBusy(false);
    }
  };

  const check = async () => {
    setBusy(true);
    await checkEmails(true);
    refresh();
    setBusy(false);
  };

  return (
    <div className={styles.group}>
      <div className={styles.rows}>
        <div className={styles.switchRow}>
          <Switch
            label={t('health.email.switch')}
            description={enabled ? t('health.email.onNote') : t('health.email.offNote')}
            checked={enabled}
            disabled={busy}
            onChange={(on) => (on ? setConfirming(true) : void change(false))}
          />
        </div>
      </div>

      {enabled && (
        <>
          {emailCheck === 'failed' && <Alert tone="warn">{t('health.email.failed')}</Alert>}
          <div className={styles.emailMeta}>
            <span>{checkedAt ? t('health.checkedAt', { date: formatDate(checkedAt, 'long') }) : t('health.email.notChecked')}</span>
            <Button variant="secondary" size="sm" icon="refresh" busy={busy} onClick={() => void check()}>
              {t('health.email.checkNow')}
            </Button>
          </div>
          {found.length > 0 ? (
            <ul className={styles.rows}>
              {found.map((finding) => (
                <BreachRow key={finding.warning} finding={finding} onDismiss={() => void dismiss([finding.warning]).catch((e: unknown) => toast({ message: errorMessage(e), tone: 'danger' }))} />
              ))}
            </ul>
          ) : (
            checkedAt && <p className={styles.clear}>{t('health.email.none')}</p>
          )}
          <p className={styles.attribution}>
            {t('health.email.source')}{' '}
            <a href={HIBP} target="_blank" rel="noopener noreferrer">
              Have I Been Pwned
            </a>
          </p>
        </>
      )}

      <Dialog
        open={confirming}
        onClose={() => setConfirming(false)}
        title={t('health.email.confirmTitle')}
        closeLabel={t('common.close')}
        footer={
          <>
            <Button variant="ghost" onClick={() => setConfirming(false)}>
              {t('common.cancel')}
            </Button>
            <Button busy={busy} onClick={() => void change(true)}>
              {t('health.email.confirm')}
            </Button>
          </>
        }
      >
        <ul className={styles.disclosure}>
          <li>{t('health.email.sendsAddresses')}</li>
          <li>{t('health.email.sendsTo')}</li>
          <li>{t('health.email.aliasNote')}</li>
          <li>{t('health.email.notStored')}</li>
        </ul>
      </Dialog>
    </div>
  );
}

function BreachRow({ finding, onDismiss }: { finding: EmailBreachFinding; onDismiss: () => void }) {
  return (
    <li className={styles.rowLine}>
      <div className={styles.row}>
        <Avatar name={finding.title} size="sm" />
        <span className={styles.rowText}>
          <b>{finding.title}</b>
          <small>
            <bdi dir="ltr">{finding.address}</bdi>
            {finding.breachDate ? ` · ${formatDate(finding.breachDate)}` : ''}
          </small>
          {finding.dataClasses.length > 0 && <small dir="ltr">{finding.dataClasses.join(', ')}</small>}
        </span>
        {finding.isNew && <span className={`${styles.tag} ${styles.danger}`}>{t('health.email.new')}</span>}
      </div>
      <div className={styles.rowActions}>
        <Button variant="ghost" size="sm" onClick={onDismiss}>
          {t('health.dismiss')}
        </Button>
      </div>
    </li>
  );
}
