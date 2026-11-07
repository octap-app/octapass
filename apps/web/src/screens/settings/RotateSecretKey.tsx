import { Button, Checkbox, Dialog, useToast } from '@octapass/ui';
import { isVaultError, type NewRecoveryKit } from '@octapass/vault-client';
import { useEffect, useState, type FormEvent } from 'react';
import { useService, useSession } from '../../app/ServiceContext';
import { Alert } from '../../components/Alert';
import { PasswordInput } from '../../components/PasswordInput';
import { t } from '../../i18n';
import { errorMessage } from '../../lib/errors';
import { RecoveryKitSheet } from '../auth/RecoveryKitSheet';
import styles from './DeleteAccount.module.css';

/**
 * Settings → Security → Replace Secret Key: the master password, then the new Recovery Kit. The
 * kit can't be skipped or closed away: it's the only copy of the new key off this device.
 */
export function RotateSecretKey({ open, onClose }: { open: boolean; onClose: () => void }) {
  const service = useService();
  const session = useSession();
  const toast = useToast();
  const [password, setPassword] = useState('');
  const [newRecoveryCode, setNewRecoveryCode] = useState(false);
  const [error, setError] = useState<string>();
  const [formError, setFormError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [kit, setKit] = useState<NewRecoveryKit>();
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    if (!open) return;
    setPassword('');
    setNewRecoveryCode(false);
    setError(undefined);
    setFormError(undefined);
    setKit(undefined);
    setSaved(false);
  }, [open]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setFormError(undefined);
    if (!password) {
      setError(t('validation.passwordRequired'));
      return;
    }
    setError(undefined);
    setBusy(true);
    try {
      setKit(await service.rotateSecretKey!({ password, newRecoveryCode }));
    } catch (e) {
      if (isVaultError(e, 'invalidCredentials')) setError(t('changePassword.wrongCurrent'));
      else setFormError(errorMessage(e));
    } finally {
      setPassword('');
      setBusy(false);
    }
  }

  function finish() {
    toast({ message: t('rotateSecretKey.done'), tone: 'success' });
    onClose();
  }

  if (kit) {
    return (
      <Dialog open={open} onClose={() => undefined} closeLabel={t('common.close')} title={t('rotateSecretKey.kitTitle')} size="md">
        <div className={styles.step}>
          <p>{t('rotateSecretKey.kitBody')}</p>
          <RecoveryKitSheet kit={kit} />
          <Button variant="secondary" icon="printer" onClick={() => window.print()}>
            {t('kit.print')}
          </Button>
          <Checkbox label={t('reset.kitConfirm')} checked={saved} onChange={(e) => setSaved(e.target.checked)} />
          <div className={styles.footer}>
            <Button disabled={!saved} onClick={finish}>
              {t('kit.continue')}
            </Button>
          </div>
        </div>
      </Dialog>
    );
  }

  return (
    <Dialog open={open} onClose={busy ? () => undefined : onClose} closeLabel={t('common.close')} title={t('rotateSecretKey.title')} size="md">
      <form className={styles.step} onSubmit={submit} noValidate>
        <p>{t('rotateSecretKey.intro')}</p>
        {formError && <Alert>{formError}</Alert>}
        <input type="email" name="username" autoComplete="username" value={session.email ?? ''} readOnly hidden />
        <PasswordInput label={t('fields.masterPassword')} autoComplete="current-password" autoFocus value={password} onChange={(e) => setPassword(e.target.value)} error={error} />
        <Checkbox label={t('rotateSecretKey.newRecoveryCode')} checked={newRecoveryCode} onChange={(e) => setNewRecoveryCode(e.target.checked)} />
        <Alert tone="info">{t('rotateSecretKey.signsOut')}</Alert>
        <div className={styles.footer}>
          <Button variant="secondary" disabled={busy} onClick={onClose}>
            {t('common.cancel')}
          </Button>
          <Button type="submit" busy={busy}>
            {t('rotateSecretKey.submit')}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
