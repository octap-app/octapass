import { Avatar, Button, IconButton, Select, TextField } from '@octapass/ui';
import { isValidEmail, isVaultError, type OrgMember, type OrgRole } from '@octapass/vault-client';
import { useState, type FormEvent } from 'react';
import { ConfirmDialog } from '../../components/ConfirmDialog';
import { formatDate, t } from '../../i18n';
import { useAction } from '../../lib/useAction';
import { useOrganisationData, useOrganisations } from '../../lib/useOrganisation';
import { Section } from '../settings/SettingsPage';
import styles from '../sharing/Sharing.module.css';

const ROLES: OrgRole[] = ['owner', 'admin', 'member'];

export function orgRoleOptions(roles: OrgRole[] = ROLES) {
  return roles.map((role) => ({ value: role, label: t(`organisation.role_${role}`) }));
}

/** Members and pending invites. Only owners change roles or remove an owner. */
export function MembersPanel({ owner }: { owner: boolean }) {
  const organisations = useOrganisations()!;
  const { data } = useOrganisationData((o) => o.listOrgMembers());
  const { busy, run } = useAction();
  const [email, setEmail] = useState('');
  const [role, setRole] = useState<OrgRole>('member');
  const [emailError, setEmailError] = useState<string>();
  const [removing, setRemoving] = useState<OrgMember>();
  const [orphaning, setOrphaning] = useState(false);

  function invite(event: FormEvent) {
    event.preventDefault();
    if (!isValidEmail(email)) return setEmailError(t('validation.email'));
    setEmailError(undefined);
    void run('invite', () => organisations.inviteOrgMember(email, role), t('organisation.invited', { email })).then((done) => done && setEmail(''));
  }

  if (!data) return <p className={styles.empty}>{t('common.loading')}</p>;
  return (
    <Section id="members" title={t('organisation.tabMembers')}>
      <ul className={styles.list} aria-label={t('organisation.tabMembers')}>
        {data.members.map((member) => (
          <li key={member.accountId} className={styles.person}>
            <div className={styles.who}>
              <Avatar name={member.email} />
              <div className={styles.whoText}>
                <span className={styles.name}>{member.isYou ? t('members.you', { email: member.email }) : member.email}</span>
                <span className={styles.meta}>
                  <span className={member.twoStep ? `${styles.badge} ${styles.ok}` : styles.badge}>{member.twoStep ? t('organisation.twoStepOn') : t('organisation.twoStepOff')}</span>
                  {member.ssoLinked && <span className={`${styles.badge} ${styles.info}`}>{t('organisation.ssoLinked')}</span>}
                </span>
              </div>
            </div>
            <div className={styles.controls}>
              {owner ? (
                <Select
                  label={t('organisation.roleOf', { email: member.email })}
                  hideLabel
                  size="sm"
                  options={orgRoleOptions()}
                  value={member.role}
                  onChange={(e) => void run(member.accountId, () => organisations.setOrgMemberRole(member.accountId, e.target.value as OrgRole), t('organisation.roleChanged'))}
                />
              ) : (
                <span className={styles.badge}>{t(`organisation.role_${member.role}`)}</span>
              )}
              {!member.isYou && (owner || member.role !== 'owner') && (
                <IconButton
                  icon="trash"
                  tone="danger"
                  label={t('organisation.remove', { email: member.email })}
                  onClick={() => {
                    setOrphaning(false);
                    setRemoving(member);
                  }}
                />
              )}
            </div>
          </li>
        ))}
        {data.invites.map((invite) => (
          <li key={invite.id} className={styles.person}>
            <div className={styles.who}>
              <Avatar name={invite.email} />
              <div className={styles.whoText}>
                <span className={styles.name}>{invite.email}</span>
                <span className={styles.meta}>
                  <span className={`${styles.badge} ${styles.info}`}>{t('family.pending')}</span>
                  <span>{t('family.invitedOn', { date: formatDate(invite.invitedAt) })}</span>
                </span>
              </div>
            </div>
            <div className={styles.controls}>
              <IconButton
                icon="close"
                label={t('family.cancelInvite', { email: invite.email })}
                disabled={busy === invite.id}
                onClick={() => void run(invite.id, () => organisations.cancelOrgInvite(invite.id), t('family.cancelled'))}
              />
            </div>
          </li>
        ))}
      </ul>
      <form className={styles.panel} onSubmit={invite} noValidate>
        <h3>{t('organisation.invite')}</h3>
        <TextField label={t('organisation.inviteEmail')} type="email" autoComplete="off" value={email} onChange={(e) => setEmail(e.target.value)} error={emailError} />
        <Select label={t('roles.label')} options={orgRoleOptions(['member', 'admin'])} value={role} onChange={(e) => setRole(e.target.value as OrgRole)} />
        <Button type="submit" size="sm" busy={busy === 'invite'}>
          {t('organisation.inviteAction')}
        </Button>
      </form>
      <ConfirmDialog
        open={removing !== undefined}
        onClose={() => setRemoving(undefined)}
        title={t('organisation.removeTitle', { email: removing?.email ?? '' })}
        confirmLabel={t('common.remove')}
        onConfirm={async () => {
          if (!removing) return;
          try {
            await organisations.removeOrgMember(removing.accountId, { orphanVaults: orphaning });
          } catch (error) {
            if (isVaultError(error, 'orgVaultOrphaned')) setOrphaning(true);
            throw error;
          }
        }}
      >
        {orphaning ? t('organisation.removeOrphans') : t('organisation.removeBody')}
      </ConfirmDialog>
    </Section>
  );
}
