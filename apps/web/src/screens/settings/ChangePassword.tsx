import { Button, Dialog, useToast } from '@octapass/ui';
import { isVaultError } from '@octapass/vault-client';
import { useEffect, useState, type FormEvent } from 'react';
import { useService, useSession } from '../../app/ServiceContext';
import { Alert } from '../../components/Alert';
import { PasswordInput } from '../../components/PasswordInput';
import { StrengthHint } from '../../components/StrengthHint';
import { t } from '../../i18n';
import { errorMessage } from '../../lib/errors';
import { useClientPolicies } from '../../lib/useOrganisation';
import { MIN_SCORE } from '../auth/SignUp';
import styles from './DeleteAccount.module.css';

/**
 * Settings → Security → Master password: the current one, then a new one. The Secret Key and
 * recovery code stay; other devices are signed out.
 */
export function ChangePassword({ open, onClose }: { open: boolean; onClose: () => void }) {
  const service = useService();
  const session = useSession();
  const toast = useToast();
  const [current, setCurrent] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [errors, setErrors] = useState<{ current?: string; password?: string; confirm?: string }>({});
  const [formError, setFormError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const estimate = service.estimateStrength(password);
  const { minPasswordLength } = useClientPolicies();

  useEffect(() => {
    if (!open) return;
    setCurrent('');
    setPassword('');
    setConfirm('');
    setErrors({});
    setFormError(undefined);
  }, [open]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    const next: typeof errors = {};
    if (!current) next.current = t('validation.passwordRequired');
    if (estimate.score < MIN_SCORE) next.password = password ? t('validation.passwordTooWeak') : t('changePassword.newRequired');
    else if (minPasswordLength && password.length < minPasswordLength) next.password = t('organisation.passwordTooShort', { length: minPasswordLength });
    else if (password === current) next.password = t('changePassword.same');
    if (confirm !== password) next.confirm = t('validation.passwordsDontMatch');
    setErrors(next);
    setFormError(undefined);
    if (Object.keys(next).length) return;
    setBusy(true);
    try {
      await service.changeMasterPassword!({ currentPassword: current, newPassword: password });
      toast({ message: t('changePassword.done'), tone: 'success' });
      setBusy(false);
      onClose();
    } catch (e) {
      if (isVaultError(e, 'invalidCredentials')) setErrors({ current: t('changePassword.wrongCurrent') });
      else setFormError(errorMessage(e));
      setCurrent('');
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onClose={busy ? () => undefined : onClose} closeLabel={t('common.close')} title={t('changePassword.title')} size="md">
      <form className={styles.step} onSubmit={submit} noValidate>
        <p>{t('changePassword.intro')}</p>
        {formError && <Alert>{formError}</Alert>}
        <input type="email" name="username" autoComplete="username" value={session.email ?? ''} readOnly hidden />
        <PasswordInput label={t('changePassword.current')} autoComplete="current-password" autoFocus value={current} onChange={(e) => setCurrent(e.target.value)} error={errors.current} />
        <div>
          <PasswordInput label={t('reset.newPassword')} autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} error={errors.password} />
          <StrengthHint estimate={estimate} empty={!password} />
        </div>
        <PasswordInput label={t('fields.confirmPassword')} autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} error={errors.confirm} />
        <Alert tone="info">{t('changePassword.signsOut')}</Alert>
        <div className={styles.footer}>
          <Button variant="secondary" disabled={busy} onClick={onClose}>
            {t('common.cancel')}
          </Button>
          <Button type="submit" busy={busy}>
            {t('changePassword.submit')}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
