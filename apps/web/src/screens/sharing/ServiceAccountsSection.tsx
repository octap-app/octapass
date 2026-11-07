import { Button, IconButton, Select, Spinner, Switch, TextField, useToast } from '@octapass/ui';
import type { ServiceAccount, Vault } from '@octapass/vault-client';
import { useState, type FormEvent } from 'react';
import { ConfirmDialog } from '../../components/ConfirmDialog';
import { formatDate, t } from '../../i18n';
import { useAction } from '../../lib/useAction';
import { useSharing, useSharingData } from '../../lib/useSharing';
import { Section } from '../settings/SettingsPage';
import styles from './Sharing.module.css';

const EXPIRY_DAYS = { never: 0, days30: 30, days90: 90, days365: 365 } as const;
type Expiry = keyof typeof EXPIRY_DAYS;

const label = (account: ServiceAccount) => account.name ?? t('serviceAccounts.unnamed', { id: account.id.slice(-8) });

/** A vault's service accounts, for its managers. A token is shown once, right after it's made. */
export function ServiceAccountsSection({ vault }: { vault: Vault }) {
  const sharing = useSharing()!;
  const toast = useToast();
  const { data: accounts } = useSharingData((s) => s.listServiceAccounts(vault.id), [vault.id]);
  const [name, setName] = useState('');
  const [canWrite, setCanWrite] = useState(false);
  const [expiry, setExpiry] = useState<Expiry>('never');
  const [token, setToken] = useState<string>();
  const [revoking, setRevoking] = useState<ServiceAccount>();
  const { run, busy } = useAction();

  const create = (event: FormEvent) => {
    event.preventDefault();
    const days = EXPIRY_DAYS[expiry];
    const expiresAt = days > 0 ? new Date(Date.now() + days * 86_400_000).toISOString() : undefined;
    void run('create', async () => {
      const created = await sharing.createServiceAccount(vault.id, { name, role: canWrite ? 'write' : 'read', expiresAt });
      setName('');
      setToken(created.token);
    });
  };

  const revoke = async () => {
    if (!revoking) return;
    await sharing.revokeServiceAccount(vault.id, revoking.id);
    toast({ message: t('serviceAccounts.revokedToast'), tone: 'success' });
  };

  return (
    <Section id="service-accounts" title={t('serviceAccounts.title')} description={t('serviceAccounts.help')}>
      {!accounts ? (
        <p className={styles.empty}>
          <Spinner size={18} />
        </p>
      ) : accounts.length === 0 ? (
        <p className={styles.empty}>{t('serviceAccounts.empty')}</p>
      ) : (
        <ul className={styles.list}>
          {accounts.map((account) => (
            <li key={account.id} className={styles.person}>
              <div className={styles.who}>
                <div className={styles.whoText}>
                  <span className={styles.name}>{label(account)}</span>
                  <span className={styles.meta}>
                    {t(`serviceAccounts.role.${account.role}`)} ·{' '}
                    {account.revokedAt
                      ? t('serviceAccounts.revoked', { date: formatDate(account.revokedAt) })
                      : account.lastUsedAt
                        ? t('serviceAccounts.lastUsed', { date: formatDate(account.lastUsedAt) })
                        : t('serviceAccounts.neverUsed')}
                    {account.expiresAt && !account.revokedAt && <> · {t('serviceAccounts.expiresOn', { date: formatDate(account.expiresAt) })}</>}
                  </span>
                  {account.needsNewToken && !account.revokedAt && <span className={styles.meta}>{t('serviceAccounts.needsNewToken')}</span>}
                </div>
              </div>
              {!account.revokedAt && <IconButton icon="trash" tone="danger" label={t('serviceAccounts.revoke', { name: label(account) })} onClick={() => setRevoking(account)} />}
            </li>
          ))}
        </ul>
      )}

      <form className={styles.panel} onSubmit={create}>
        <TextField label={t('serviceAccounts.name')} hint={t('serviceAccounts.nameHint')} value={name} maxLength={64} onChange={(event) => setName(event.target.value)} />
        <Switch label={t('serviceAccounts.canWrite')} description={t('serviceAccounts.canWriteHelp')} checked={canWrite} onChange={setCanWrite} />
        <Select
          label={t('serviceAccounts.expires')}
          value={expiry}
          onChange={(event) => setExpiry(event.target.value as Expiry)}
          options={(Object.keys(EXPIRY_DAYS) as Expiry[]).map((value) => ({ value, label: t(`serviceAccounts.${value}`) }))}
        />
        <Button type="submit" variant="secondary" icon="plus" busy={busy === 'create'} disabled={!name.trim()}>
          {t('serviceAccounts.create')}
        </Button>
      </form>

      <ConfirmDialog
        open={token !== undefined}
        onClose={() => setToken(undefined)}
        title={t('serviceAccounts.tokenTitle')}
        confirmLabel={t('serviceAccounts.done')}
        tone="primary"
        onConfirm={async () => undefined}
      >
        <p>{t('serviceAccounts.tokenBody')}</p>
        <TextField label={t('serviceAccounts.tokenLabel')} value={token ?? ''} readOnly dir="ltr" onFocus={(event) => event.target.select()} />
        <Button
          variant="secondary"
          size="sm"
          icon="copy"
          onClick={() => {
            void navigator.clipboard.writeText(token ?? '').then(() => toast({ message: t('serviceAccounts.copied'), tone: 'success' }));
          }}
        >
          {t('serviceAccounts.copy')}
        </Button>
      </ConfirmDialog>

      <ConfirmDialog open={revoking !== undefined} onClose={() => setRevoking(undefined)} title={t('serviceAccounts.revokeTitle')} confirmLabel={t('serviceAccounts.revokeAction')} onConfirm={revoke}>
        <p>{t('serviceAccounts.revokeBody')}</p>
      </ConfirmDialog>
    </Section>
  );
}
