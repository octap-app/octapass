import { Avatar, Button, Dialog, EmptyState, IconButton, Segmented, Select, useToast } from '@octapass/ui';
import type { EmergencyAccessLevel, EmergencyContact, Vault } from '@octapass/vault-client';
import { useState } from 'react';
import { useNavigate } from 'react-router';
import { AccountFinder } from '../../components/AccountFinder';
import { Alert } from '../../components/Alert';
import { ConfirmDialog } from '../../components/ConfirmDialog';
import { formatDate, t } from '../../i18n';
import { useAction } from '../../lib/useAction';
import { useVaults } from '../../lib/useItems';
import { useSharing, useSharingData } from '../../lib/useSharing';
import { PageHeader } from '../PageHeader';
import { Section } from '../settings/SettingsPage';
import settingsStyles from '../settings/SettingsPage.module.css';
import styles from '../sharing/Sharing.module.css';
import { TakeoverDialog } from './TakeoverDialog';

const WAIT_DAYS = [1, 2, 3, 7, 14, 30];

type Confirm = { kind: 'remove'; contact: EmergencyContact } | { kind: 'request'; contact: EmergencyContact } | { kind: 'stepDown'; contact: EmergencyContact };

/** Emergency access (plan 06): trusted contacts both ways, and the request, deny and release timeline. */
export function EmergencyPage() {
  const sharing = useSharing();
  const vaults = useVaults();
  const { data } = useSharingData((s) => s.listEmergencyContacts());
  const [confirm, setConfirm] = useState<Confirm>();
  const [taking, setTaking] = useState<EmergencyContact>();
  const [renewing, setRenewing] = useState<EmergencyContact>();

  if (!sharing) {
    return (
      <div className={settingsStyles.page}>
        <PageHeader title={t('emergency.title')} />
        <EmptyState icon="lifebuoy" title={t('emergency.unavailable')} />
      </div>
    );
  }

  return (
    <div className={settingsStyles.page}>
      <PageHeader title={t('emergency.title')} subtitle={t('emergency.subtitle')} />
      <div className={settingsStyles.body}>
        <Alert tone="info">{t('emergency.how')}</Alert>

        <Section id="contacts" title={t('emergency.contacts')}>
          {!data ? (
            <p className={styles.empty}>{t('common.loading')}</p>
          ) : data.granted.length === 0 ? (
            <p className={styles.empty}>{t('emergency.noContacts')}</p>
          ) : (
            <ul className={styles.list}>
              {data.granted.map((contact) => (
                <GrantedRow key={contact.id} contact={contact} vaults={vaults} onRemove={() => setConfirm({ kind: 'remove', contact })} onRenew={() => setRenewing(contact)} />
              ))}
            </ul>
          )}
        </Section>

        <Section id="add" title={t('emergency.add')}>
          <AddContact vaults={vaults} />
        </Section>

        <Section id="received" title={t('emergency.received')}>
          {!data ? (
            <p className={styles.empty}>{t('common.loading')}</p>
          ) : data.received.length === 0 ? (
            <p className={styles.empty}>{t('emergency.noReceived')}</p>
          ) : (
            <ul className={styles.list}>
              {data.received.map((contact) => (
                <ReceivedRow key={contact.id} contact={contact} onRequest={() => setConfirm({ kind: 'request', contact })} onStepDown={() => setConfirm({ kind: 'stepDown', contact })} onTakeOver={() => setTaking(contact)} />
              ))}
            </ul>
          )}
        </Section>
      </div>

      <EmergencyConfirm confirm={confirm} onClose={() => setConfirm(undefined)} />
      <TakeoverDialog contact={taking} onClose={() => setTaking(undefined)} />
      <RenewDialog contact={renewing} onClose={() => setRenewing(undefined)} />
    </div>
  );
}

function scopeLabel(contact: EmergencyContact, vaults: Vault[] | undefined): string {
  if (contact.scope.type === 'account') return t('emergency.scopeAccount');
  const { vaultId } = contact.scope;
  return t('emergency.scopeVault', { vault: vaults?.find((v) => v.id === vaultId)?.name ?? t('scopes.vault') });
}

/** A rotated vault's key, sealed to the contact again once the user has seen their fingerprint. */
function RenewDialog({ contact, onClose }: { contact: EmergencyContact | undefined; onClose: () => void }) {
  const sharing = useSharing()!;
  const toast = useToast();
  if (!contact) return null;
  return (
    <Dialog open onClose={onClose} closeLabel={t('common.close')} title={t('emergency.renewTitle', { email: contact.contactEmail })} size="md">
      <p>{t('emergency.renewBody')}</p>
      <AccountFinder
        initialEmail={contact.contactEmail}
        submitLabel={t('emergency.renew')}
        onSubmit={async (account) => {
          await sharing.renewEmergencyKey(contact.id, account);
          toast({ message: t('emergency.renewed', { email: contact.contactEmail }), tone: 'success' });
          onClose();
        }}
      />
    </Dialog>
  );
}

function GrantedRow({ contact, vaults, onRemove, onRenew }: { contact: EmergencyContact; vaults: Vault[] | undefined; onRemove: () => void; onRenew: () => void }) {
  const sharing = useSharing()!;
  const { busy, run } = useAction();
  return (
    <li className={styles.person}>
      <div className={styles.who}>
        <Avatar name={contact.contactEmail} />
        <div className={styles.whoText}>
          <span className={styles.name}>{contact.contactEmail}</span>
          <span className={styles.meta}>
            <span>{scopeLabel(contact, vaults)}</span>
            <span>{contact.organiserRecovery ? t('emergency.organiserRecovery') : contact.accessLevel === 'view' ? t('emergency.view') : t('emergency.takeover')}</span>
            <span>{t('emergency.days', { count: contact.waitDays })}</span>
          </span>
        </div>
      </div>
      <div className={styles.controls}>
        <IconButton icon="trash" tone="danger" label={t('emergency.remove', { email: contact.contactEmail })} onClick={onRemove} />
      </div>
      <div className={styles.status}>
        {contact.keyStale && (
          <Alert
            tone="warn"
            action={
              <Button size="sm" variant="secondary" onClick={onRenew}>
                {t('emergency.renew')}
              </Button>
            }
          >
            {t('emergency.keyStale')}
          </Alert>
        )}
        {contact.status === 'idle' ? (
          <span className={styles.badge}>{t('emergency.statusIdle')}</span>
        ) : contact.status === 'requested' ? (
          <Alert
            tone="warn"
            action={
              <span className={styles.controls}>
                <Button size="sm" variant="secondary" disabled={busy !== undefined} onClick={() => void run('deny', () => sharing.denyEmergencyAccess(contact.id), t('emergency.denied'))}>
                  {t('emergency.deny')}
                </Button>
                <Button size="sm" busy={busy === 'approve'} disabled={busy !== undefined} onClick={() => void run('approve', () => sharing.approveEmergencyAccess(contact.id), t('emergency.approved', { email: contact.contactEmail }))}>
                  {t('emergency.approve')}
                </Button>
              </span>
            }
          >
            {t('emergency.statusRequested', { date: formatDate(contact.requestedAt!), release: formatDate(contact.releasesAt!, 'long') })}
          </Alert>
        ) : (
          <Alert
            tone="info"
            action={
              <Button size="sm" variant="secondary" busy={busy === 'deny'} onClick={() => void run('deny', () => sharing.denyEmergencyAccess(contact.id), t('emergency.denied'))}>
                {t('emergency.denyReleased')}
              </Button>
            }
          >
            {t('emergency.statusReleased', { date: formatDate(contact.releasedAt!, 'long') })}
          </Alert>
        )}
      </div>
    </li>
  );
}

function AddContact({ vaults }: { vaults: Vault[] | undefined }) {
  const sharing = useSharing()!;
  const toast = useToast();
  const [waitDays, setWaitDays] = useState(7);
  const [accessLevel, setAccessLevel] = useState<EmergencyAccessLevel>('view');
  const [scope, setScope] = useState('account');
  const owned = (vaults ?? []).filter((v) => v.role === 'owner' && !v.untrusted);

  return (
    <div className={styles.panel}>
      <AccountFinder
        submitLabel={t('emergency.addAction')}
        options={
          <>
            <div className={styles.fields}>
              <Select
                label={t('emergency.waitDays')}
                options={WAIT_DAYS.map((days) => ({ value: String(days), label: t('emergency.days', { count: days }) }))}
                value={String(waitDays)}
                onChange={(e) => setWaitDays(Number(e.target.value))}
              />
              <Select
                label={t('emergency.scope')}
                options={[{ value: 'account', label: t('emergency.scopeAccount') }, ...owned.map((v) => ({ value: v.id, label: t('emergency.scopeVault', { vault: v.name }) }))]}
                value={scope}
                onChange={(e) => setScope(e.target.value)}
              />
            </div>
            <div className={styles.fields}>
              <Segmented<EmergencyAccessLevel>
                label={t('emergency.accessLevel')}
                value={accessLevel}
                onChange={setAccessLevel}
                options={[
                  { value: 'view', label: t('emergency.view') },
                  { value: 'takeover', label: t('emergency.takeover') },
                ]}
              />
              <p className={styles.meta}>{accessLevel === 'view' ? t('emergency.viewHelp') : t('emergency.takeoverHelp')}</p>
            </div>
            {accessLevel === 'takeover' && scope === 'account' && <Alert tone="warn">{t('emergency.takeoverWarning')}</Alert>}
            {accessLevel === 'takeover' && scope !== 'account' && <Alert tone="warn">{t('emergency.takeoverAccountOnly')}</Alert>}
          </>
        }
        disabled={accessLevel === 'takeover' && scope !== 'account'}
        onSubmit={async (account) => {
          await sharing.addEmergencyContact({ account, waitDays, accessLevel, scope: scope === 'account' ? { type: 'account' } : { type: 'vault', vaultId: scope } });
          toast({ message: t('emergency.added', { email: account.email }), tone: 'success' });
        }}
      />
    </div>
  );
}

function ReceivedRow({ contact, onRequest, onStepDown, onTakeOver }: { contact: EmergencyContact; onRequest: () => void; onStepDown: () => void; onTakeOver: () => void }) {
  const navigate = useNavigate();
  const email = contact.grantorEmail;
  const status =
    contact.status === 'idle'
      ? t('emergency.receivedIdle', { email, days: t('emergency.days', { count: contact.waitDays }) })
      : contact.status === 'requested'
        ? t('emergency.receivedRequested', { email, date: formatDate(contact.requestedAt!), release: formatDate(contact.releasesAt!, 'long') })
        : contact.organiserRecovery
          ? t('emergency.organiserReleased', { date: formatDate(contact.releasedAt!, 'long') })
          : t('emergency.receivedReleased', { date: formatDate(contact.releasedAt!, 'long') });
  return (
    <li className={styles.person}>
      <div className={styles.who}>
        <Avatar name={email} />
        <div className={styles.whoText}>
          <span className={styles.name}>{email}</span>
          <span className={styles.meta}>{status}</span>
          {contact.keyStale && contact.status === 'released' && <span className={styles.meta}>{t('emergency.receivedStale', { email })}</span>}
        </div>
      </div>
      <div className={styles.controls}>
        <Button variant="ghost" size="sm" onClick={onStepDown}>
          {t('emergency.stepDown')}
        </Button>
        {contact.status === 'idle' && (
          <Button variant="secondary" size="sm" icon="lifebuoy" onClick={onRequest}>
            {t('emergency.request')}
          </Button>
        )}
        {contact.status === 'released' && !contact.organiserRecovery && (
          <Button size="sm" icon="vault" onClick={() => navigate(`/emergency/${contact.id}`)}>
            {t('emergency.open')}
          </Button>
        )}
        {contact.status === 'released' && contact.accessLevel === 'takeover' && contact.scope.type === 'account' && (
          <Button size="sm" variant="danger" icon="key" onClick={onTakeOver}>
            {t('takeover.action')}
          </Button>
        )}
      </div>
    </li>
  );
}

function EmergencyConfirm({ confirm, onClose }: { confirm: Confirm | undefined; onClose: () => void }) {
  const sharing = useSharing()!;
  const toast = useToast();
  if (!confirm) return null;
  const { contact } = confirm;
  const content = {
    remove: {
      title: t('emergency.removeTitle', { email: contact.contactEmail }),
      body: t('emergency.removeBody'),
      label: t('common.remove'),
      tone: 'danger' as const,
      action: async () => {
        await sharing.removeEmergencyContact(contact.id);
        toast({ message: t('emergency.removed', { email: contact.contactEmail }), tone: 'success' });
      },
    },
    request: {
      title: t('emergency.requestTitle', { email: contact.grantorEmail }),
      body: t('emergency.requestBody', { email: contact.grantorEmail }),
      label: t('emergency.request'),
      tone: 'primary' as const,
      action: async () => {
        await sharing.requestEmergencyAccess(contact.id);
        const updated = (await sharing.listEmergencyContacts()).received.find((c) => c.id === contact.id);
        toast({ message: t('emergency.requested', { date: formatDate(updated?.releasesAt ?? new Date().toISOString(), 'long') }), tone: 'success' });
      },
    },
    stepDown: {
      title: t('emergency.stepDownTitle', { email: contact.grantorEmail }),
      body: t('emergency.stepDownBody', { email: contact.grantorEmail }),
      label: t('emergency.stepDown'),
      tone: 'danger' as const,
      action: async () => {
        await sharing.removeEmergencyContact(contact.id);
        toast({ message: t('emergency.steppedDown', { email: contact.grantorEmail }), tone: 'success' });
      },
    },
  }[confirm.kind];
  return (
    <ConfirmDialog open title={content.title} confirmLabel={content.label} tone={content.tone} onConfirm={content.action} onClose={onClose}>
      {content.body}
    </ConfirmDialog>
  );
}
