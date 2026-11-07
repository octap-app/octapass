import { Avatar, Button, EmptyState, Icon, IconButton, KeyFingerprint, Select, Spinner, TextField, useToast } from '@octapass/ui';
import type { Vault, VaultMember, VaultRole } from '@octapass/vault-client';
import { useState, type FormEvent } from 'react';
import { Link, useNavigate, useParams } from 'react-router';
import { AccountFinder } from '../../components/AccountFinder';
import { Alert } from '../../components/Alert';
import { ConfirmDialog } from '../../components/ConfirmDialog';
import { formatDate, t } from '../../i18n';
import { useAction } from '../../lib/useAction';
import { useVaults } from '../../lib/useItems';
import { useSharing, useSharingData } from '../../lib/useSharing';
import { PageHeader } from '../PageHeader';
import { Row, Section } from '../settings/SettingsPage';
import settingsStyles from '../settings/SettingsPage.module.css';
import { canChangeMember, canManage, roleLabel, roleOptions } from './roles';
import { ServiceAccountsSection } from './ServiceAccountsSection';
import styles from './Sharing.module.css';

type Confirm = { kind: 'remove'; member: VaultMember } | { kind: 'leave' };

/** Sharing → a vault: who's in it, their roles and fingerprints, adding and removing people. */
export function VaultMembersPage() {
  const { vaultId = '' } = useParams();
  const vaults = useVaults();
  const sharing = useSharing();
  const vault = vaults?.find((v) => v.id === vaultId);

  if (!sharing) return <EmptyState icon="users" title={t('sharing.unavailable')} />;
  if (!vaults) {
    return (
      <div className={settingsStyles.page}>
        <Spinner size={24} />
      </div>
    );
  }
  if (!vault || vault.type === 'personal') {
    return (
      <div className={settingsStyles.page}>
        <PageHeader title={t('sharing.title')} />
        <EmptyState icon="users" title={t('members.notFound')} action={<BackLink />} />
      </div>
    );
  }
  return <VaultMembers key={vault.id} vault={vault} />;
}

function BackLink() {
  return (
    <Link to="/sharing" className={styles.back}>
      <Icon name="chevronLeft" size={16} />
      {t('members.back')}
    </Link>
  );
}

function VaultMembers({ vault }: { vault: Vault }) {
  const sharing = useSharing()!;
  const navigate = useNavigate();
  const toast = useToast();
  const { data: members, error } = useSharingData((s) => s.listMembers(vault.id), [vault.id]);
  const [confirm, setConfirm] = useState<Confirm>();
  const [inviteRole, setInviteRole] = useState<VaultRole>('write');
  const manager = canManage(vault.role) && !vault.untrusted;
  const shared = vault.type === 'shared';
  const owners = members?.filter((m) => m.role === 'owner') ?? [];
  const lastOwner = vault.role === 'owner' && owners.length <= 1;
  const unverified = members?.filter((m) => !m.verified).length ?? 0;

  return (
    <div className={settingsStyles.page}>
      <PageHeader
        title={vault.name}
        subtitle={
          <>
            <BackLink /> · {t('sharing.roleIn', { role: roleLabel(vault.role) })}
          </>
        }
        actions={
          <Button variant="secondary" size="sm" icon="vault" onClick={() => navigate(`/items/v-${vault.id}`)}>
            {t('members.openVault')}
          </Button>
        }
      />
      <div className={settingsStyles.body}>
        {vault.untrusted && <Alert tone="warn">{t('vault.untrustedBody', { vault: vault.name })}</Alert>}
        {vault.type === 'family' && (
          <Alert tone="info" action={<Link to="/sharing#family">{t('members.familyLink')}</Link>}>
            {t('members.familyVault')}
          </Alert>
        )}

        {shared && vault.role !== 'read' && !vault.untrusted && <RenameVault vault={vault} />}

        <Section id="members" title={t('vault.members')} description={unverified > 0 ? t('members.unverifiedCount', { count: unverified }) : undefined}>
          {error ? (
            <Alert>{t('errors.unexpected')}</Alert>
          ) : !members ? (
            <p className={styles.empty}>{t('common.loading')}</p>
          ) : (
            <ul className={styles.list}>
              {members.map((member) => (
                <MemberRow key={member.accountId ?? member.email} vault={vault} member={member} editable={shared && manager && !member.isYou && canChangeMember(vault.role, member.role)} onRemove={() => setConfirm({ kind: 'remove', member })} />
              ))}
            </ul>
          )}
        </Section>

        {shared && manager && (
          <Section id="invite" title={t('members.invite')} description={t('members.inviteHelp')}>
            <div className={styles.panel}>
              <AccountFinder
                submitLabel={t('members.inviteAction')}
                options={<Select label={t('roles.label')} options={roleOptions(vault.role)} value={inviteRole} onChange={(e) => setInviteRole(e.target.value as VaultRole)} />}
                onSubmit={async (account) => {
                  await sharing.addMember(vault.id, account, inviteRole);
                  toast({ message: t('members.invited', { email: account.email, vault: vault.name }), tone: 'success' });
                }}
              />
            </div>
          </Section>
        )}

        {shared && manager && <ServiceAccountsSection vault={vault} />}

        {shared && (
          <Section id="leave" title={t('members.leave')}>
            <Row label={t('members.leave')} description={lastOwner ? t('members.lastOwner') : t('members.leaveHelp')}>
              <Button variant="danger" size="sm" icon="signOut" disabled={lastOwner} onClick={() => setConfirm({ kind: 'leave' })}>
                {t('members.leave')}
              </Button>
            </Row>
          </Section>
        )}
      </div>

      <ConfirmDialog
        open={confirm !== undefined}
        onClose={() => setConfirm(undefined)}
        title={confirm?.kind === 'remove' ? t('members.removeTitle', { email: confirm.member.email }) : t('members.leaveTitle', { vault: vault.name })}
        confirmLabel={confirm?.kind === 'remove' ? t('members.removeAction') : t('members.leave')}
        onConfirm={async () => {
          if (confirm?.kind === 'remove') {
            await sharing.removeMember(vault.id, confirm.member.accountId!);
            toast({ message: t('members.removed', { email: confirm.member.email }), tone: 'success' });
          } else {
            await sharing.leaveVault(vault.id);
            toast({ message: t('members.left', { vault: vault.name }), tone: 'success' });
            navigate('/sharing', { replace: true });
          }
        }}
      >
        {confirm?.kind === 'remove' ? t('members.removeBody', { vault: vault.name }) : t('members.leaveBody')}
      </ConfirmDialog>
    </div>
  );
}

function RenameVault({ vault }: { vault: Vault }) {
  const sharing = useSharing()!;
  const { busy, run } = useAction();
  const [name, setName] = useState(vault.name);

  function submit(event: FormEvent) {
    event.preventDefault();
    if (name.trim() && name.trim() !== vault.name) void run('rename', () => sharing.renameVault(vault.id, name), t('members.renamed'));
  }

  return (
    <section className={settingsStyles.card}>
      <form className={styles.rename} onSubmit={submit}>
        <TextField label={t('members.rename')} maxLength={80} value={name} onChange={(e) => setName(e.target.value)} />
        <Button type="submit" variant="secondary" busy={busy === 'rename'} disabled={!name.trim() || name.trim() === vault.name}>
          {t('common.rename')}
        </Button>
      </form>
    </section>
  );
}

function MemberRow({ vault, member, editable, onRemove }: { vault: Vault; member: VaultMember; editable: boolean; onRemove: () => void }) {
  const sharing = useSharing()!;
  const { busy, run } = useAction();
  const [comparing, setComparing] = useState(false);

  return (
    <li className={styles.person}>
      <div className={styles.who}>
        <Avatar name={member.email} />
        <div className={styles.whoText}>
          <span className={styles.name}>{member.isYou ? t('members.you', { email: member.email }) : member.email}</span>
          <span className={styles.meta}>
            {member.verified ? (
              <span className={`${styles.badge} ${styles.ok}`}>
                <Icon name="check" size={12} />
                {t('fingerprint.verified')}
              </span>
            ) : (
              <span className={`${styles.badge} ${styles.warn}`}>{t('fingerprint.unverified')}</span>
            )}
            {member.keyLog === 'verified' && (
              <span className={`${styles.badge} ${styles.ok}`} title={t('keyLog.verifiedHelp')}>
                {t('keyLog.verified')}
              </span>
            )}
            {member.keyLog === 'notLogged' && (
              <span className={`${styles.badge} ${styles.info}`} title={t('keyLog.notLoggedHelp')}>
                {t('keyLog.notLogged')}
              </span>
            )}
            {member.keyLog === 'failed' && (
              <span className={`${styles.badge} ${styles.warn}`} title={t('keyLog.failedHelp')}>
                {t('keyLog.failed')}
              </span>
            )}
            {member.addedAt && <span>{t('members.added', { date: formatDate(member.addedAt) })}</span>}
          </span>
        </div>
      </div>
      <div className={styles.controls}>
        {!member.isYou && member.fingerprint && (
          <Button variant="ghost" size="sm" icon="fingerprint" aria-expanded={comparing} onClick={() => setComparing((c) => !c)}>
            {t('fingerprint.verify')}
          </Button>
        )}
        {editable ? (
          <>
            <Select
              label={t('roles.label')}
              hideLabel
              size="sm"
              options={roleOptions(vault.role).map((o) => ({ ...o, label: roleLabel(o.value as VaultRole) }))}
              value={member.role}
              disabled={busy === 'role'}
              onChange={(e) => {
                const role = e.target.value as VaultRole;
                void run('role', () => sharing.changeRole(vault.id, member.accountId!, role), t('members.roleChanged', { email: member.email, role: roleLabel(role) }));
              }}
            />
            <IconButton icon="trash" tone="danger" label={t('members.remove', { email: member.email })} onClick={onRemove} />
          </>
        ) : (
          <span className={styles.badge}>{roleLabel(member.role)}</span>
        )}
      </div>
      {comparing && member.fingerprint && (
        <div className={styles.expand}>
          <KeyFingerprint size="sm" label={t('fingerprint.title')} emojiLabel={t('fingerprint.emoji')} digits={member.fingerprint.digits} emoji={member.fingerprint.emoji} />
          <p>{t('fingerprint.compareHelp', { email: member.email })}</p>
          {!member.verified && (
            <Button
              variant="secondary"
              size="sm"
              icon="check"
              busy={busy === 'verify'}
              onClick={() => void run('verify', () => sharing.markVerified({ accountId: member.accountId!, fingerprint: member.fingerprint! }), t('fingerprint.markedVerified'))}
            >
              {t('fingerprint.markVerified')}
            </Button>
          )}
        </div>
      )}
    </li>
  );
}
