import { Logo } from '@octapass/ui';
import type { NewRecoveryKit } from '@octapass/vault-client';
import { QrCode } from '../../components/QrCode';
import { formatDate, t } from '../../i18n';
import styles from './RecoveryKitSheet.module.css';

/** What a new device scans to fill in the email, server and Secret Key. Never the recovery code. */
export function setupUri(kit: NewRecoveryKit): string {
  const params = new URLSearchParams({ email: kit.email, server: kit.serverUrl, secretKey: kit.secretKey });
  return `octapass://setup?${params}`;
}

/** The Recovery Kit, laid out to print on one page. Made on this device; nothing is uploaded. */
export function RecoveryKitSheet({ kit }: { kit: NewRecoveryKit }) {
  return (
    <article className={styles.sheet} aria-labelledby="kit-title">
      <header className={styles.header}>
        <Logo variant="tile" size={36} />
        <div>
          <h2 id="kit-title" className={styles.title}>
            {t('kit.sheetTitle')}
          </h2>
          <p className={styles.meta}>{t('kit.createdOn', { date: formatDate(kit.createdAt) })}</p>
        </div>
      </header>

      <dl className={styles.fields}>
        <div>
          <dt>{t('fields.email')}</dt>
          <dd>{kit.email}</dd>
        </div>
        <div>
          <dt>{t('kit.server')}</dt>
          <dd>{kit.serverUrl}</dd>
        </div>
        <div className={styles.secret}>
          <dt>{t('fields.secretKey')}</dt>
          <dd className="mono">{kit.secretKey}</dd>
        </div>
        <div className={styles.password}>
          <dt>{t('fields.masterPassword')}</dt>
          <dd aria-label={t('kit.writeItDown')}>
            <span className={styles.blank} />
          </dd>
        </div>
      </dl>

      <div className={styles.qrRow}>
        <QrCode value={setupUri(kit)} size={124} label={t('kit.qrLabel')} />
        <p>{t('kit.qrHelp')}</p>
      </div>

      <section className={styles.recovery}>
        <h3>{t('kit.recoveryCode')}</h3>
        {kit.recoveryCode ? <p className={`mono ${styles.code}`}>{kit.recoveryCode}</p> : <p>{t('kit.recoveryKept')}</p>}
        <p className={styles.small}>{t('kit.recoveryHelp')}</p>
      </section>

      <p className={styles.small}>{t('kit.keepSafe')}</p>
    </article>
  );
}
