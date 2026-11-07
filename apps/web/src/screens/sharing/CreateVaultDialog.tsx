import { Button, Dialog, TextField } from '@octapass/ui';
import { useEffect, useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router';
import { Alert } from '../../components/Alert';
import { t } from '../../i18n';
import { errorMessage } from '../../lib/errors';
import { useSharing } from '../../lib/useSharing';
import styles from './Dialogs.module.css';

/** Names a new shared vault, creates it, and opens its members page to invite people. */
export function CreateVaultDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const sharing = useSharing();
  const navigate = useNavigate();
  const [name, setName] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();

  useEffect(() => {
    if (!open) return;
    setName('');
    setError(undefined);
  }, [open]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!sharing || !name.trim()) return;
    setBusy(true);
    setError(undefined);
    try {
      const vault = await sharing.createVault(name);
      onClose();
      navigate(`/sharing/vaults/${vault.id}`);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onClose={busy ? () => undefined : onClose} closeLabel={t('common.close')} title={t('sharing.newVaultTitle')} description={t('sharing.newVaultHelp')}>
      <form className={styles.form} onSubmit={submit}>
        <TextField label={t('sharing.vaultName')} placeholder={t('sharing.vaultNamePlaceholder')} maxLength={80} autoFocus value={name} onChange={(e) => setName(e.target.value)} />
        {error && <Alert>{error}</Alert>}
        <div className={styles.footer}>
          <Button variant="secondary" disabled={busy} onClick={onClose}>
            {t('common.cancel')}
          </Button>
          <Button type="submit" icon="plus" busy={busy} disabled={!name.trim()}>
            {t('sharing.create')}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
