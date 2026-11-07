import { Avatar, Button, IconButton, Select, useToast } from '@octapass/ui';
import type { Family, FamilyInvite } from '@octapass/vault-client';
import { useState } from 'react';
import { useNavigate } from 'react-router';
import { AccountFinder } from '../../components/AccountFinder';
import { Alert } from '../../components/Alert';
import { ConfirmDialog } from '../../components/ConfirmDialog';
import { formatDate, t } from '../../i18n';
import { useAction } from '../../lib/useAction';
import { useSharing, useSharingData } from '../../lib/useSharing';
import { Row } from '../settings/SettingsPage';
import styles from './Sharing.module.css';

type Confirm = { kind: 'remove'; accountId: string; email: string } | { kind: 'leave' } | { kind: 'delete' };

/** Sharing → Family: create one, invite up to the limit, accept invitations, leave or remove. */
export function FamilyPanel() {
  const sharing = useSharing()!;
  const toast = useToast();
  const { data } = useSharingData((s) => s.getFamily());
  const { busy, run } = useAction();
  const [confirm, setConfirm] = useState<Confirm>();

  if (!data) return <p className={styles.empty}>{t('common.loading')}</p>;
  const { family, invitations } = data;

  return (
    <>
      {invitations.map((invite) => (
        <Invitation key={invite.familyId} invite={invite} busy={busy === invite.familyId} run={run} />
      ))}
      {family ? (
        <FamilyMembers family={family} busy={busy} run={run} onConfirm={setConfirm} />
      ) : (
        <Row label={t('family.help', { count: 6 })}>
          <Button size="sm" icon="home" busy={busy === 'create'} onClick={() => void run('create', () => sharing.createFamily(), t('family.created'))}>
            {t('family.create')}
          </Button>
        </Row>
      )}
      <ConfirmDialog
        open={confirm !== undefined}
        onClose={() => setConfirm(undefined)}
        title={confirm?.kind === 'remove' ? t('family.removeTitle', { email: confirm.email }) : confirm?.kind === 'leave' ? t('family.leaveTitle') : t('family.deleteTitle')}
        confirmLabel={confirm?.kind === 'remove' ? t('common.remove') : confirm?.kind === 'leave' ? t('family.leave') : t('family.delete')}
        onConfirm={async () => {
          if (confirm?.kind === 'remove') {
            await sharing.removeFamilyMember(confirm.accountId);
            toast({ message: t('family.removed', { email: confirm.email }), tone: 'success' });
          } else if (confirm?.kind === 'leave') {
            await sharing.leaveFamily();
            toast({ message: t('family.left'), tone: 'success' });
          } else {
            await sharing.deleteFamily();
            toast({ message: t('family.deleted'), tone: 'success' });
          }
        }}
      >
        {confirm?.kind === 'remove' ? t('family.removeBody') : confirm?.kind === 'leave' ? t('family.leaveBody') : t('family.deleteBody')}
      </ConfirmDialog>
    </>
  );
}

type Run = ReturnType<typeof useAction>['run'];

function Invitation({ invite, busy, run }: { invite: FamilyInvite; busy: boolean; run: Run }) {
  const sharing = useSharing()!;
  return (
    <div className={styles.person}>
      <div className={styles.who}>
        <Avatar name={invite.organiserEmail} />
        <div className={styles.whoText}>
          <span className={styles.name}>{t('family.invitation', { email: invite.organiserEmail })}</span>
          <span className={styles.meta}>{t('family.invitedOn', { date: formatDate(invite.invitedAt) })}</span>
        </div>
      </div>
      <div className={styles.controls}>
        <Button variant="secondary" size="sm" disabled={busy} onClick={() => void run(invite.familyId, () => sharing.declineFamilyInvite(invite.familyId), t('family.declined'))}>
          {t('family.decline')}
        </Button>
        <Button size="sm" busy={busy} onClick={() => void run(invite.familyId, () => sharing.acceptFamilyInvite(invite.familyId), t('family.joined'))}>
          {t('family.accept')}
        </Button>
      </div>
    </div>
  );
}

function FamilyMembers({ family, busy, run, onConfirm }: { family: Family; busy: string | undefined; run: Run; onConfirm: (c: Confirm) => void }) {
  const sharing = useSharing()!;
  const toast = useToast();
  const navigate = useNavigate();
  const used = family.members.length + family.invites.length;
  const full = used >= family.maxMembers;

  return (
    <>
      <Row label={t('family.vault')} description={t('family.count', { members: used, max: family.maxMembers })}>
        <Button variant="secondary" size="sm" icon="home" onClick={() => navigate(`/items/v-${family.vaultId}`)}>
          {t('members.openVault')}
        </Button>
      </Row>
      <ul className={styles.list} aria-label={t('family.title')}>
        {family.members.map((member) => (
          <li key={member.accountId} className={styles.person}>
            <div className={styles.who}>
              <Avatar name={member.email} />
              <div className={styles.whoText}>
                <span className={styles.name}>{member.isYou ? t('members.you', { email: member.email }) : member.email}</span>
                <span className={styles.meta}>
                  <span className={member.role === 'organiser' ? `${styles.badge} ${styles.ok}` : styles.badge}>{member.role === 'organiser' ? t('family.organiser') : t('family.member')}</span>
                </span>
              </div>
            </div>
            {family.isOrganiser && !member.isYou && (
              <div className={styles.controls}>
                <IconButton icon="trash" tone="danger" label={t('family.remove', { email: member.email })} onClick={() => onConfirm({ kind: 'remove', accountId: member.accountId, email: member.email })} />
              </div>
            )}
          </li>
        ))}
        {family.invites.map((invite) => (
          <li key={invite.accountId} className={styles.person}>
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
                disabled={busy === invite.accountId}
                onClick={() => void run(invite.accountId, () => sharing.cancelFamilyInvite(invite.accountId), t('family.cancelled'))}
              />
            </div>
          </li>
        ))}
      </ul>
      {family.isOrganiser && (
        <div className={styles.panel}>
          <h3>{t('family.invite')}</h3>
          {full ? (
            <p className={styles.meta}>{t('family.full')}</p>
          ) : (
            <AccountFinder
              submitLabel={t('family.inviteAction')}
              onSubmit={async (account) => {
                await sharing.inviteToFamily(account);
                toast({ message: t('family.invited', { email: account.email }), tone: 'success' });
              }}
            />
          )}
        </div>
      )}
      {!family.isOrganiser && <OrganiserRecovery family={family} />}
      <Row label={family.isOrganiser ? t('family.delete') : t('family.leave')} description={family.isOrganiser ? t('family.deleteBody') : t('family.leaveBody')}>
        <Button variant="danger" size="sm" icon={family.isOrganiser ? 'trash' : 'signOut'} onClick={() => onConfirm(family.isOrganiser ? { kind: 'delete' } : { kind: 'leave' })}>
          {family.isOrganiser ? t('family.delete') : t('family.leave')}
        </Button>
      </Row>
    </>
  );
}

const RECOVERY_WAIT_DAYS = [1, 2, 3, 7, 14, 30];

/** As a family member: opt in to the organiser helping recover this account (plan 06). Off by default. */
function OrganiserRecovery({ family }: { family: Family }) {
  const sharing = useSharing()!;
  const toast = useToast();
  const { data } = useSharingData((s) => s.listEmergencyContacts());
  const [waitDays, setWaitDays] = useState(7);
  const [confirmOff, setConfirmOff] = useState(false);
  const organiser = family.members.find((m) => m.accountId === family.organiserId);
  const record = data?.granted.find((c) => c.organiserRecovery);

  return (
    <div className={styles.panel}>
      <h3>{t('family.recovery.title')}</h3>
      {!data ? (
        <p className={styles.meta}>{t('common.loading')}</p>
      ) : record ? (
        <>
          <p>{t('family.recovery.on', { email: record.contactEmail, days: t('emergency.days', { count: record.waitDays }) })}</p>
          <Button variant="secondary" size="sm" onClick={() => setConfirmOff(true)}>
            {t('family.recovery.turnOff')}
          </Button>
        </>
      ) : (
        <>
          <p>{t('family.recovery.help', { email: organiser?.email ?? '' })}</p>
          <Alert tone="warn">{t('family.recovery.warning')}</Alert>
          <AccountFinder
            initialEmail={organiser?.email}
            submitLabel={t('family.recovery.turnOn')}
            options={
              <Select
                label={t('emergency.waitDays')}
                options={RECOVERY_WAIT_DAYS.map((days) => ({ value: String(days), label: t('emergency.days', { count: days }) }))}
                value={String(waitDays)}
                onChange={(e) => setWaitDays(Number(e.target.value))}
              />
            }
            onSubmit={async (account) => {
              await sharing.enableOrganiserRecovery({ account, waitDays });
              toast({ message: t('family.recovery.turnedOn'), tone: 'success' });
            }}
          />
        </>
      )}
      <ConfirmDialog
        open={confirmOff}
        title={t('family.recovery.offTitle')}
        confirmLabel={t('family.recovery.turnOff')}
        onClose={() => setConfirmOff(false)}
        onConfirm={async () => {
          await sharing.removeEmergencyContact(record!.id);
          toast({ message: t('family.recovery.turnedOff'), tone: 'success' });
        }}
      >
        {t('family.recovery.offBody')}
      </ConfirmDialog>
    </div>
  );
}
