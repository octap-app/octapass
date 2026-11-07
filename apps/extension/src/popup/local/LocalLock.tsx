import { Button } from '@octapass/ui';
import { isVaultError } from '@octapass/vault-client';
import { useService } from '@octapass/web/src/app/ServiceContext';
import { PasswordInput } from '@octapass/web/src/components/PasswordInput';
import { t } from '@octapass/web/src/i18n';
import { errorMessage } from '@octapass/web/src/lib/errors';
import { AuthLayout } from '@octapass/web/src/screens/auth/AuthLayout';
import signIn from '@octapass/web/src/screens/auth/SignIn.module.css';
import { useState, type FormEvent } from 'react';
import { tx } from '../../i18n';

/** The lock screen of a vault on this device only: the master password, no account to sign out of. */
export function LocalLock() {
  const service = useService();
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!password) return setError(t('validation.passwordRequired'));
    setBusy(true);
    setError(undefined);
    try {
      await service.unlock(password);
    } catch (e) {
      // A vault bound to the desktop app's chip opens only with the app.
      setError(isVaultError(e, 'deviceUnlockUnsupported') ? tx('local.needsApp') : errorMessage(e));
      setPassword('');
      setBusy(false);
    }
  }

  return (
    <AuthLayout title={t('lock.title')} subtitle={tx('local.lockedSubtitle')}>
      <form className={signIn.form} onSubmit={submit} noValidate>
        <PasswordInput label={t('fields.masterPassword')} autoComplete="current-password" autoFocus value={password} onChange={(e) => setPassword(e.target.value)} error={error} />
        <Button type="submit" size="lg" block busy={busy} icon="lock">
          {t('lock.unlock')}
        </Button>
      </form>
    </AuthLayout>
  );
}
