import { Button, EmptyState, Icon, Spinner } from '@octapass/ui';
import type { RecoveryContact } from '@octapass/vault-client';
import { Link, useNavigate } from 'react-router';
import { Alert } from '../../components/Alert';
import { t } from '../../i18n';
import { errorMessage } from '../../lib/errors';
import { useHealth } from '../../lib/health';
import { providerName } from '../../lib/maskedEmail';
import { PageHeader } from '../PageHeader';
import { Row } from './HealthRow';
import styles from './HealthPage.module.css';

/** The recovery map (plan 01): which email or phone can reset which logins. */
export function RecoveryMapPage() {
  const { report, error } = useHealth();
  const navigate = useNavigate();

  return (
    <div className={styles.page}>
      <PageHeader
        title={t('recoveryMap.title')}
        subtitle={t('recoveryMap.subtitle')}
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
          </div>
        ) : report.recovery.length === 0 ? (
          <EmptyState icon="mail" title={t('recoveryMap.empty')}>{t('recoveryMap.emptyBody')}</EmptyState>
        ) : (
          <>
            <p className={styles.help}>{t('recoveryMap.help')}</p>
            {report.recovery.map((contact) => (
              <Contact key={`${contact.kind}:${contact.value}`} contact={contact} />
            ))}
            <Alert tone="info">{t('recoveryMap.breachGap')}</Alert>
          </>
        )}
      </div>
    </div>
  );
}

function Contact({ contact }: { contact: RecoveryContact }) {
  const { account, aliasProvider, identityId } = contact;
  return (
    <section className={styles.group} aria-label={contact.value}>
      <h2 className={styles.groupTitle}>
        <Icon name={contact.kind === 'email' ? 'mail' : 'phone'} size={20} /> {t('recoveryMap.canReset', { count: contact.logins.length, value: contact.value })}
      </h2>
      <p className={styles.help}>
        {aliasProvider ? (
          <span className={styles.tag}>{t('recoveryMap.masked', { provider: providerName(aliasProvider) })}</span>
        ) : contact.kind === 'email' && account ? (
          <Link to={`/items/all/${account.itemId}`} className={[styles.tag, !account.twoStep && styles.warn].filter(Boolean).join(' ')}>
            {account.twoStep ? t('recoveryMap.accountTwoStep') : t('recoveryMap.accountNoTwoStep')}
          </Link>
        ) : contact.kind === 'email' ? (
          <span className={styles.tag}>{t('recoveryMap.accountMissing')}</span>
        ) : null}{' '}
        {identityId && (
          <Link to={`/items/all/${identityId}`} className={styles.tag}>
            {t('recoveryMap.fromIdentity')}
          </Link>
        )}
      </p>
      <ul className={styles.rows}>
        {contact.logins.map((entry) => (
          <Row key={entry.itemId} entry={entry} />
        ))}
      </ul>
    </section>
  );
}
