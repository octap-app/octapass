import { Button, Checkbox, Dialog } from '@octapass/ui';
import { isVaultError, type EmergencyContact, type NewRecoveryKit } from '@octapass/vault-client';
import { useEffect, useState, type FormEvent } from 'react';
import { useService } from '../../app/ServiceContext';
import { Alert } from '../../components/Alert';
import { PasswordInput } from '../../components/PasswordInput';
import { StrengthHint } from '../../components/StrengthHint';
import { t } from '../../i18n';
import { errorMessage } from '../../lib/errors';
import { useSharing } from '../../lib/useSharing';
import { RecoveryKitSheet } from '../auth/RecoveryKitSheet';
import { MIN_SCORE } from '../auth/SignUp';
import styles from '../settings/DeleteAccount.module.css';

/**
 * As the contact of a released takeover record (plan 06): the user's own master password, then a
 * new one for the grantor, then the new Recovery Kit, which is the only copy and can't be skipped.
 */
export function TakeoverDialog({ contact, onClose }: { contact: EmergencyContact | undefined; onClose: () => void }) {
  const service = useService();
  const sharing = useSharing()!;
  const [own, setOwn] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [errors, setErrors] = useState<{ own?: string; password?: string; confirm?: string }>({});
  const [formError, setFormError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [kit, setKit] = useState<NewRecoveryKit>();
  const [saved, setSaved] = useState(false);
  const estimate = service.estimateStrength(password);

  useEffect(() => {
    setOwn('');
    setPassword('');
    setConfirm('');
    setErrors({});
    setFormError(undefined);
    setKit(undefined);
    setSaved(false);
  }, [contact?.id]);

  if (!contact) return null;
  const email = contact.grantorEmail;

  async function submit(event: FormEvent) {
    event.preventDefault();
    const next: typeof errors = {};
    if (!own) next.own = t('validation.passwordRequired');
    if (estimate.score < MIN_SCORE) next.password = password ? t('validation.passwordTooWeak') : t('changePassword.newRequired');
    if (confirm !== password) next.confirm = t('validation.passwordsDontMatch');
    setErrors(next);
    setFormError(undefined);
    if (Object.keys(next).length) return;
    setBusy(true);
    try {
      setKit(await sharing.takeOverAccount(contact!.id, { contactPassword: own, newPassword: password }));
    } catch (e) {
      if (isVaultError(e, 'invalidCredentials')) setErrors({ own: t('takeover.wrongOwn') });
      else setFormError(errorMessage(e));
      setOwn('');
    } finally {
      setBusy(false);
    }
  }

  if (kit) {
    return (
      <Dialog open onClose={() => undefined} closeLabel={t('common.close')} title={t('takeover.kitTitle')} size="md">
        <div className={styles.step}>
          <p>{t('takeover.kitBody', { email })}</p>
          <RecoveryKitSheet kit={kit} />
          <Button variant="secondary" icon="printer" onClick={() => window.print()}>
            {t('kit.print')}
          </Button>
          <Checkbox label={t('reset.kitConfirm')} checked={saved} onChange={(e) => setSaved(e.target.checked)} />
          <div className={styles.footer}>
            <Button disabled={!saved} onClick={onClose}>
              {t('kit.continue')}
            </Button>
          </div>
        </div>
      </Dialog>
    );
  }

  return (
    <Dialog open onClose={busy ? () => undefined : onClose} closeLabel={t('common.close')} title={t('takeover.title', { email })} size="md">
      <form className={styles.step} onSubmit={submit} noValidate>
        <Alert tone="warn">{t('takeover.warning', { email })}</Alert>
        {formError && <Alert>{formError}</Alert>}
        <PasswordInput label={t('takeover.ownPassword')} autoComplete="current-password" autoFocus value={own} onChange={(e) => setOwn(e.target.value)} error={errors.own} />
        <div>
          <PasswordInput label={t('takeover.newPassword', { email })} autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} error={errors.password} />
          <StrengthHint estimate={estimate} empty={!password} />
        </div>
        <PasswordInput label={t('fields.confirmPassword')} autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} error={errors.confirm} />
        <div className={styles.footer}>
          <Button variant="secondary" disabled={busy} onClick={onClose}>
            {t('common.cancel')}
          </Button>
          <Button type="submit" variant="danger" busy={busy}>
            {t('takeover.submit')}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
