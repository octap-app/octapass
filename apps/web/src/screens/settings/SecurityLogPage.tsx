import { EmptyState, Icon, Spinner, type IconName } from '@octapass/ui';
import type { SecurityEvent, SecurityEventType } from '@octapass/vault-client';
import { Link } from 'react-router';
import { formatDate, t, type MessageKey } from '../../i18n';
import { useSharing, useSharingData } from '../../lib/useSharing';
import { PageHeader } from '../PageHeader';
import sharingStyles from '../sharing/Sharing.module.css';
import styles from './SettingsPage.module.css';

const ICONS: Record<SecurityEventType, IconName> = {
  'emergency-contact-added': 'userPlus',
  'emergency-contact-removed': 'users',
  'emergency-access-requested': 'lifebuoy',
  'emergency-access-denied': 'shield',
  'emergency-access-approved': 'key',
  'emergency-access-released': 'key',
  'two-step-enabled': 'shield',
  'two-step-disabled': 'shield',
  'authenticator-changed': 'phone',
  'security-key-added': 'passkey',
  'security-key-removed': 'passkey',
  'recovery-codes-renewed': 'refresh',
  'recovery-code-used': 'key',
  'two-step-locked': 'alert',
  'trusted-devices-forgotten': 'monitor',
  'password-changed': 'lock',
  'password-reset': 'key',
  'vault-exported': 'download',
  'secret-key-rotated': 'key',
  'vault-key-rotated': 'refresh',
  'emergency-takeover': 'alert',
  'organiser-recovery-enabled': 'lifebuoy',
  'organiser-recovery-disabled': 'lifebuoy',
  'service-account-created': 'key',
  'service-account-revoked': 'key',
  'service-account-read': 'key',
  'service-account-wrote': 'key',
  'service-account-denied': 'alert',
  'connect-secret-read': 'key',
};

/** An export's format, and whether the file held the attachments. */
function exportDetails(event: SecurityEvent): string | undefined {
  if (event.connect) return t('securityLog.connectDetails', { client: event.connect.clientName, reference: event.connect.reference });
  if (event.serviceAccountId) return t('securityLog.serviceAccountDetails', { id: event.serviceAccountId.slice(-8) });
  if (!event.exportFormat) return undefined;
  if (event.exportFormat === 'encrypted' && event.exportAttachments) return t('securityLog.exportDetails.encryptedFiles');
  return t(`securityLog.exportDetails.${event.exportFormat}`);
}

/** Settings → Security log: the account's own events, newest first (`GET /v1/security-log`). */
export function SecurityLogPage() {
  const sharing = useSharing();
  const { data: events } = useSharingData((s) => s.getSecurityLog());
  const back = (
    <Link to="/settings#security" className={sharingStyles.back}>
      <Icon name="chevronLeft" size={16} />
      {t('securityLog.back')}
    </Link>
  );

  return (
    <div className={styles.page}>
      <PageHeader
        title={t('securityLog.title')}
        subtitle={
          <>
            {back} · {t('securityLog.subtitle')}
          </>
        }
      />
      <div className={styles.body}>
        {!sharing ? (
          <EmptyState icon="history" title={t('sharing.unavailable')} />
        ) : (
          <div className={styles.card}>
            {!events ? (
              <p className={sharingStyles.empty}>
                <Spinner size={18} />
              </p>
            ) : events.length === 0 ? (
              <p className={sharingStyles.empty}>{t('securityLog.empty')}</p>
            ) : (
              <ol className={sharingStyles.list}>
                {events.map((event, i) => {
                  const details = exportDetails(event);
                  return (
                    <li key={`${event.createdAt}-${i}`} className={sharingStyles.person}>
                      <div className={sharingStyles.who}>
                        <span className={sharingStyles.vaultIcon}>
                          <Icon name={ICONS[event.type] ?? 'history'} size={18} />
                        </span>
                        <div className={sharingStyles.whoText}>
                          <span className={sharingStyles.name}>{t(`securityLog.events.${event.type}` as MessageKey, { email: event.otherAccountEmail ?? t('securityLog.someone'), device: event.deviceName ?? t('securityLog.unknownDevice') })}</span>
                          <span className={sharingStyles.meta}>
                            {details && <>{details} · </>}
                            <time dateTime={event.createdAt}>{formatDate(event.createdAt, 'long')}</time>
                          </span>
                        </div>
                      </div>
                    </li>
                  );
                })}
              </ol>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
