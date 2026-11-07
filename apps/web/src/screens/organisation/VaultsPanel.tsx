import { Button, Dialog, IconButton, Select, TextField, useToast } from '@octapass/ui';
import type { OrgGroup, OrgVault, VaultRole } from '@octapass/vault-client';
import { useState, type FormEvent } from 'react';
import { Alert } from '../../components/Alert';
import { PasswordInput } from '../../components/PasswordInput';
import { t } from '../../i18n';
import { errorMessage } from '../../lib/errors';
import { useAction } from '../../lib/useAction';
import { useOrganisationData, useOrganisations } from '../../lib/useOrganisation';
import { Section } from '../settings/SettingsPage';
import { roleLabel } from '../sharing/roles';
import styles from '../sharing/Sharing.module.css';

const GROUP_ROLES: VaultRole[] = ['read', 'write', 'manage'];

const vaultName = (vault: OrgVault) => vault.name ?? t('organisation.vaultWithId', { id: vault.shortId });

/** Organisation vaults and which groups reach them. An admin without a vault's key sees only part of its id. */
export function VaultsPanel({ owner }: { owner: boolean }) {
  const organisations = useOrganisations()!;
  const { data: vaults } = useOrganisationData((o) => o.listOrgVaults());
  const { data: groups } = useOrganisationData((o) => o.listOrgGroups());
  const { busy, run } = useAction();
  const [name, setName] = useState('');
  const [deleting, setDeleting] = useState<OrgVault>();

  function create(event: FormEvent) {
    event.preventDefault();
    if (!name.trim()) return;
    void run('create', () => organisations.createOrgVault(name.trim()), t('organisation.vaultCreated')).then((done) => done && setName(''));
  }

  if (!vaults || !groups) return <p className={styles.empty}>{t('common.loading')}</p>;
  return (
    <Section id="vaults" title={t('organisation.tabVaults')} description={t('organisation.vaultsHelp')}>
      {vaults.length === 0 && <p className={styles.empty}>{t('organisation.noVaults')}</p>}
      {vaults.map((vault) => (
        <VaultRow key={vault.id} vault={vault} groups={groups} owner={owner} onDelete={() => setDeleting(vault)} />
      ))}
      <form className={styles.panel} onSubmit={create}>
        <h3>{t('organisation.newVault')}</h3>
        <TextField label={t('organisation.vaultName')} maxLength={100} value={name} onChange={(e) => setName(e.target.value)} />
        <Button type="submit" size="sm" busy={busy === 'create'}>
          {t('organisation.createVault')}
        </Button>
      </form>
      <DeleteVault vault={deleting} onClose={() => setDeleting(undefined)} />
    </Section>
  );
}

function VaultRow({ vault, groups, owner, onDelete }: { vault: OrgVault; groups: OrgGroup[]; owner: boolean; onDelete: () => void }) {
  const organisations = useOrganisations()!;
  const { busy, run } = useAction();
  const [groupId, setGroupId] = useState('');
  const [role, setRole] = useState<VaultRole>('read');
  const linked = new Set(vault.groups.map((link) => link.groupId));
  const unlinked = groups.filter((group) => !linked.has(group.id));

  return (
    <div className={styles.panel}>
      <div className={styles.person}>
        <div className={styles.whoText}>
          <h3>{vaultName(vault)}</h3>
          <span className={styles.meta}>
            <span>{t('organisation.vaultMembers', { count: vault.memberCount })}</span>
            {vault.rotationPending && <span className={`${styles.badge} ${styles.info}`}>{t('organisation.rotationDue')}</span>}
            {vault.managerCount === 0 && <span className={styles.badge}>{t('organisation.noManagers')}</span>}
          </span>
        </div>
        {owner && (
          <div className={styles.controls}>
            <IconButton icon="trash" tone="danger" label={t('organisation.deleteVaultNamed', { name: vaultName(vault) })} onClick={onDelete} />
          </div>
        )}
      </div>
      <ul className={styles.list} aria-label={t('organisation.vaultGroups', { name: vaultName(vault) })}>
        {vault.groups.map((link) => {
          const group = groups.find((g) => g.id === link.groupId);
          return (
            <li key={link.groupId} className={styles.person}>
              <span className={styles.who}>{group?.name ?? link.groupId}</span>
              <div className={styles.controls}>
                <Select
                  label={t('organisation.groupRole', { name: group?.name ?? '' })}
                  hideLabel
                  size="sm"
                  options={GROUP_ROLES.map((value) => ({ value, label: roleLabel(value) }))}
                  value={link.role}
                  onChange={(e) => void run(link.groupId, () => organisations.linkOrgVaultGroup(vault.id, link.groupId, e.target.value as VaultRole))}
                />
                <IconButton
                  icon="close"
                  label={t('organisation.unlink', { name: group?.name ?? '' })}
                  disabled={busy === link.groupId}
                  onClick={() => void run(link.groupId, () => organisations.unlinkOrgVaultGroup(vault.id, link.groupId))}
                />
              </div>
            </li>
          );
        })}
      </ul>
      {unlinked.length > 0 && (
        <div className={styles.controls}>
          <Select
            label={t('organisation.linkGroup')}
            size="sm"
            value={groupId}
            options={[{ value: '', label: t('organisation.chooseGroup') }, ...unlinked.map((group) => ({ value: group.id, label: group.name }))]}
            onChange={(e) => setGroupId(e.target.value)}
          />
          <Select label={t('roles.label')} size="sm" value={role} options={GROUP_ROLES.map((value) => ({ value, label: roleLabel(value) }))} onChange={(e) => setRole(e.target.value as VaultRole)} />
          <Button
            variant="secondary"
            size="sm"
            disabled={!groupId}
            busy={busy === 'link'}
            onClick={() =>
              void run('link', () => organisations.linkOrgVaultGroup(vault.id, groupId, role), t('organisation.linked')).then((done) => done && setGroupId(''))
            }
          >
            {t('organisation.link')}
          </Button>
        </div>
      )}
    </div>
  );
}

function DeleteVault({ vault, onClose }: { vault: OrgVault | undefined; onClose: () => void }) {
  const organisations = useOrganisations()!;
  const toast = useToast();
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(undefined);
    try {
      await organisations.deleteOrgVault({ password, vaultId: vault!.id });
      toast({ message: t('organisation.vaultDeleted'), tone: 'success' });
      setPassword('');
      onClose();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={vault !== undefined} onClose={onClose} closeLabel={t('common.close')} title={vault ? t('organisation.deleteVaultTitle', { name: vaultName(vault) }) : ''}>
      <form onSubmit={submit} className={styles.panel}>
        {error && <Alert>{error}</Alert>}
        <p>{t('organisation.deleteVaultBody')}</p>
        <PasswordInput id="org-vault-password" label={t('organisation.masterPassword')} value={password} onChange={(e) => setPassword(e.target.value)} />
        <Button type="submit" variant="danger" size="sm" busy={busy} disabled={!password}>
          {t('organisation.deleteVault')}
        </Button>
      </form>
    </Dialog>
  );
}
