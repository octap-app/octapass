import { Button, Dialog, TextField, useToast } from '@octapass/ui';
import { isVaultError, type Organisation } from '@octapass/vault-client';
import { useState, type FormEvent } from 'react';
import { Alert } from '../../components/Alert';
import { ConfirmDialog } from '../../components/ConfirmDialog';
import { PasswordInput } from '../../components/PasswordInput';
import { t } from '../../i18n';
import { errorMessage } from '../../lib/errors';
import { useOrganisations } from '../../lib/useOrganisation';
import { Row, Section } from '../settings/SettingsPage';
import styles from '../sharing/Sharing.module.css';

/** Leaving is always possible, except for the last owner, who passes it on or deletes it. */
export function LeavePanel({ organisation }: { organisation: Organisation }) {
  const organisations = useOrganisations()!;
  const toast = useToast();
  const [leaving, setLeaving] = useState(false);
  const [orphaning, setOrphaning] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const owner = organisation.role === 'owner';

  return (
    <Section id="leave" title={t('organisation.danger')}>
      <Row label={t('organisation.leave')} description={t('organisation.leaveBody')}>
        <Button
          variant="secondary"
          size="sm"
          icon="signOut"
          onClick={() => {
            setOrphaning(false);
            setLeaving(true);
          }}
        >
          {t('organisation.leave')}
        </Button>
      </Row>
      {owner && (
        <Row label={t('organisation.delete')} description={t('organisation.deleteBody')}>
          <Button variant="danger" size="sm" icon="trash" onClick={() => setDeleting(true)}>
            {t('organisation.delete')}
          </Button>
        </Row>
      )}
      <ConfirmDialog
        open={leaving}
        onClose={() => setLeaving(false)}
        title={t('organisation.leaveTitle', { organisation: organisation.name })}
        confirmLabel={t('organisation.leave')}
        onConfirm={async () => {
          try {
            await organisations.leaveOrganisation({ orphanVaults: orphaning });
            toast({ message: t('organisation.left'), tone: 'success' });
          } catch (error) {
            if (isVaultError(error, 'orgVaultOrphaned')) setOrphaning(true);
            throw error;
          }
        }}
      >
        {orphaning ? t('organisation.removeOrphans') : t('organisation.leaveBody')}
      </ConfirmDialog>
      <DeleteOrganisation organisation={organisation} open={deleting} onClose={() => setDeleting(false)} />
    </Section>
  );
}

function DeleteOrganisation({ organisation, open, onClose }: { organisation: Organisation; open: boolean; onClose: () => void }) {
  const organisations = useOrganisations()!;
  const toast = useToast();
  const [confirmName, setConfirmName] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(undefined);
    try {
      await organisations.deleteOrganisation({ password, confirmName });
      toast({ message: t('organisation.deleted'), tone: 'success' });
      onClose();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onClose={onClose} closeLabel={t('common.close')} title={t('organisation.deleteTitle', { organisation: organisation.name })}>
      <form onSubmit={submit} className={styles.panel}>
        {error && <Alert>{error}</Alert>}
        <p>{t('organisation.deleteBody')}</p>
        <TextField label={t('organisation.deleteConfirm', { organisation: organisation.name })} autoComplete="off" value={confirmName} onChange={(e) => setConfirmName(e.target.value)} />
        <PasswordInput id="org-password" label={t('organisation.masterPassword')} value={password} onChange={(e) => setPassword(e.target.value)} />
        <Button type="submit" variant="danger" size="sm" busy={busy} disabled={confirmName !== organisation.name || !password}>
          {t('organisation.delete')}
        </Button>
      </form>
    </Dialog>
  );
}
