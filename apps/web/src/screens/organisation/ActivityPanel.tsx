import { formatDate, t, type MessageKey } from '../../i18n';
import { useOrganisationData } from '../../lib/useOrganisation';
import { Section } from '../settings/SettingsPage';
import styles from '../sharing/Sharing.module.css';

const LABELS: Record<string, MessageKey> = {
  'org-created': 'organisation.eventOrgCreated',
  'org-renamed': 'organisation.eventOrgRenamed',
  'member-invited': 'organisation.eventMemberInvited',
  'invite-cancelled': 'organisation.eventInviteCancelled',
  'invite-declined': 'organisation.eventInviteDeclined',
  'member-joined': 'organisation.eventMemberJoined',
  'member-left': 'organisation.eventMemberLeft',
  'member-removed': 'organisation.eventMemberRemoved',
  'member-role-changed': 'organisation.eventRoleChanged',
  'group-created': 'organisation.eventGroupCreated',
  'group-renamed': 'organisation.eventGroupRenamed',
  'group-deleted': 'organisation.eventGroupDeleted',
  'group-member-added': 'organisation.eventGroupMemberAdded',
  'group-member-removed': 'organisation.eventGroupMemberRemoved',
  'vault-created': 'organisation.eventVaultCreated',
  'vault-deleted': 'organisation.eventVaultDeleted',
  'vault-group-linked': 'organisation.eventVaultLinked',
  'vault-group-unlinked': 'organisation.eventVaultUnlinked',
  'access-granted': 'organisation.eventAccessGranted',
  'policies-changed': 'organisation.eventPoliciesChanged',
  'sso-changed': 'organisation.eventSsoChanged',
  'sso-removed': 'organisation.eventSsoRemoved',
  'scim-token-created': 'organisation.eventScimTokenCreated',
  'scim-token-revoked': 'organisation.eventScimTokenRevoked',
  'scim-user-provisioned': 'organisation.eventScimProvisioned',
  'scim-user-invited': 'organisation.eventScimInvited',
  'scim-user-deprovisioned': 'organisation.eventScimDeprovisioned',
  'scim-owner-kept': 'organisation.eventScimOwnerKept',
  'scim-group-created': 'organisation.eventScimGroupCreated',
  'scim-group-changed': 'organisation.eventScimGroupChanged',
  'scim-group-deleted': 'organisation.eventScimGroupDeleted',
  'scim-vault-orphaned': 'organisation.eventScimVaultOrphaned',
};

/** What admins did, newest first, kept a year. Names and ids only: never vault contents. */
export function ActivityPanel() {
  const { data } = useOrganisationData((o) => o.listOrgEvents());
  if (!data) return <p className={styles.empty}>{t('common.loading')}</p>;
  return (
    <Section id="activity" title={t('organisation.tabActivity')} description={t('organisation.activityHelp')}>
      {data.length === 0 ? (
        <p className={styles.empty}>{t('organisation.noActivity')}</p>
      ) : (
        <ul className={styles.list}>
          {data.map((event) => {
            const label = LABELS[event.type];
            return (
              <li key={event.id} className={styles.person}>
                <div className={styles.whoText}>
                  <span className={styles.name}>{label ? t(label) : event.type}</span>
                  <span className={styles.meta}>
                    {event.subject && <span>{event.subject}</span>}
                    {event.actor ? <span>{event.actor}</span> : event.type.startsWith('scim-') && <span>{t('organisation.byIdentityProvider')}</span>}
                    <span>{formatDate(event.createdAt, 'long')}</span>
                  </span>
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </Section>
  );
}
