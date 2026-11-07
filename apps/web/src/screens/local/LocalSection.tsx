import { Button, Dialog, TextField, useToast } from '@octapass/ui';
import { useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router';
import { useService, useSession } from '../../app/ServiceContext';
import { Alert } from '../../components/Alert';
import { PasswordInput } from '../../components/PasswordInput';
import { formatDate, t } from '../../i18n';
import { errorMessage } from '../../lib/errors';
import { useConfirmIdentity } from '../../lib/identityGate';
import { Row, Section } from '../settings/SettingsPage';
import styles from './local.module.css';
import { RecoveryCode } from './RecoveryCode';
import { useLocalVaults } from './useLocalVaults';

/** Settings for a vault on this device only: backups, its recovery code, Turn on sync, other vaults. */
export function LocalSection() {
  const service = useService();
  const local = service.local!;
  const session = useSession();
  const toast = useToast();
  const confirm = useConfirmIdentity();
  const navigate = useNavigate();
  const { vaults, current, reload } = useLocalVaults();
  const [code, setCode] = useState<string>();
  const [renaming, setRenaming] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const others = vaults.filter((vault) => !vault.current);

  async function run(action: () => Promise<unknown>, done?: string) {
    try {
      const result = await action();
      reload();
      if (done && result !== undefined) toast({ message: done, tone: 'success', icon: 'download' });
    } catch (e) {
      toast({ message: errorMessage(e), tone: 'danger' });
    }
  }

  async function backUp() {
    if (await confirm({ reason: t('identityGate.body') })) await run(() => local.saveBackup(), t('localVault.backedUp'));
  }

  async function showCode() {
    if (await confirm({ reason: t('identityGate.body') })) await run(async () => setCode(await local.recoveryCode()));
  }

  return (
    <Section id="local" title={t('localVault.sectionTitle')} description={t('localVault.sectionHelp')}>
      <Row label={t('localVault.nameLabel')} description={<bdi>{session.email}</bdi>}>
        <Button variant="secondary" size="sm" onClick={() => setRenaming(true)}>
          {t('localVault.rename')}
        </Button>
      </Row>
      <Row label={t('localVault.backUp')} description={current?.lastBackupAt ? t('localVault.lastBackup', { date: formatDate(current.lastBackupAt) }) : t('localVault.neverBackedUp')}>
        <Button variant="secondary" size="sm" icon="download" onClick={() => void backUp()}>
          {t('localVault.backUp')}
        </Button>
      </Row>
      <Row label={t('localVault.folder')} description={current?.backupFolder ? t('localVault.folderOn', { folder: current.backupFolder }) : t('localVault.folderOff')}>
        <Button variant="secondary" size="sm" onClick={() => void run(() => local.chooseBackupFolder(), t('localVault.folderChosen'))}>
          {current?.backupFolder ? t('localVault.changeFolder') : t('localVault.chooseFolder')}
        </Button>
        {current?.backupFolder && (
          <Button variant="ghost" size="sm" onClick={() => void run(() => local.clearBackupFolder())}>
            {t('localVault.stopFolder')}
          </Button>
        )}
      </Row>
      <Row label={t('localVault.recoveryCode')} description={code ? <RecoveryCode code={code} /> : t('localVault.showCodeHelp')}>
        {!code && (
          <Button variant="secondary" size="sm" icon="eye" onClick={() => void showCode()}>
            {t('localVault.showCode')}
          </Button>
        )}
      </Row>
      {current && <Row label={t('settings.security')} description={current.chipBound ? t('localVault.chipOn') : t('localVault.chipOff')} />}
      <Row label={t('localVault.turnOnSync')} description={t('localVault.turnOnSyncHelp')}>
        <Button size="sm" icon="refresh" onClick={() => navigate('/local/sync')}>
          {t('localVault.turnOnSync')}
        </Button>
      </Row>
      {others.length > 0 && (
        <Row label={t('localVault.otherVaults')} description={t('localVault.otherVaultsHelp')}>
          <ul className={styles.vaults}>
            {others.map((vault) => (
              <li key={vault.id} className={styles.vault}>
                <bdi>{vault.name}</bdi>
                <Button variant="ghost" size="sm" onClick={() => void run(() => local.switchTo(vault.id))}>
                  {t('localVault.open')}
                </Button>
              </li>
            ))}
          </ul>
        </Row>
      )}
      <Row label={t('localVault.addVault')} description={t('localVault.addVaultHelp')}>
        <Button variant="secondary" size="sm" onClick={() => void run(() => local.leave())}>
          {t('localVault.addVault')}
        </Button>
      </Row>
      <Row label={t('localVault.deleteVault')} description={t('localVault.deleteVaultHelp')}>
        <Button variant="danger" size="sm" icon="trash" onClick={() => setDeleting(true)}>
          {t('localVault.deleteVault')}
        </Button>
      </Row>
      <RenameDialog open={renaming} current={session.email ?? ''} onClose={() => setRenaming(false)} onDone={reload} />
      <DeleteDialog open={deleting} name={session.email ?? ''} onClose={() => setDeleting(false)} />
    </Section>
  );
}

function RenameDialog({ open, current, onClose, onDone }: { open: boolean; current: string; onClose: () => void; onDone: () => void }) {
  const service = useService();
  const [name, setName] = useState(current);
  const [error, setError] = useState<string>();

  async function submit(event: FormEvent) {
    event.preventDefault();
    try {
      await service.local!.rename(name);
      onDone();
      onClose();
    } catch (e) {
      setError(errorMessage(e));
    }
  }

  return (
    <Dialog open={open} onClose={onClose} closeLabel={t('common.close')} title={t('localVault.renameTitle')} size="md">
      <form className={styles.form} onSubmit={submit} noValidate>
        <TextField label={t('localVault.nameLabel')} autoFocus value={name} onChange={(e) => setName(e.target.value)} error={error} />
        <Button type="submit" block>
          {t('common.save')}
        </Button>
      </form>
    </Dialog>
  );
}

function DeleteDialog({ open, name, onClose }: { open: boolean; name: string; onClose: () => void }) {
  const service = useService();
  const toast = useToast();
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(undefined);
    try {
      await service.local!.remove(password);
      toast({ message: t('localVault.deleted'), tone: 'success' });
    } catch (e) {
      setError(errorMessage(e));
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onClose={busy ? () => undefined : onClose} closeLabel={t('common.close')} title={t('localVault.deleteTitle', { name })} size="md">
      <form className={styles.form} onSubmit={submit} noValidate>
        {error && <Alert>{error}</Alert>}
        <p>{t('localVault.deleteBody')}</p>
        <PasswordInput label={t('fields.masterPassword')} autoComplete="current-password" autoFocus value={password} onChange={(e) => setPassword(e.target.value)} />
        <Button type="submit" variant="danger" block busy={busy}>
          {t('localVault.deleteAction')}
        </Button>
      </form>
    </Dialog>
  );
}
