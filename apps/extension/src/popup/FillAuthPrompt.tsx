import { Button } from '@octapass/ui';
import { isVaultError } from '@octapass/vault-client';
import { useService, useSession } from '@octapass/web/src/app/ServiceContext';
import { Alert } from '@octapass/web/src/components/Alert';
import { PasswordInput } from '@octapass/web/src/components/PasswordInput';
import { t } from '@octapass/web/src/i18n';
import { errorMessage } from '@octapass/web/src/lib/errors';
import { AuthLayout } from '@octapass/web/src/screens/auth/AuthLayout';
import lock from '@octapass/web/src/screens/auth/Lock.module.css';
import { useEffect, useState, type FormEvent } from 'react';
import { useParams } from 'react-router';
import { useExtension } from './ExtensionContext';

/** The window an autofill opens when "Ask on every fill" is on. Device auth, or the master password. */
export function FillAuthPrompt() {
  const { id = '' } = useParams();
  const { api } = useExtension();
  const service = useService();
  const session = useSession();
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [device, setDevice] = useState(false);

  useEffect(() => {
    let live = true;
    service.canConfirmIdentityWithDevice?.().then(
      (yes) => live && setDevice(yes),
      () => undefined,
    );
    return () => {
      live = false;
    };
  }, [service]);

  async function finish(proof: { password: string } | { device: true }) {
    setBusy(true);
    setError(undefined);
    try {
      await service.confirmIdentity!(proof);
      await api.approveFillAuth(id, true);
      window.close();
    } catch (e) {
      setError(isVaultError(e, 'invalidCredentials') ? t('identityGate.wrongPassword') : errorMessage(e));
      setBusy(false);
    }
  }

  function cancel() {
    void api.approveFillAuth(id, false).finally(() => window.close());
  }

  return (
    <AuthLayout title={t('identityGate.title')} subtitle={session.email}>
      <form
        className={lock.form}
        onSubmit={(event: FormEvent) => {
          event.preventDefault();
          void finish({ password });
        }}
        noValidate
      >
        <Alert tone="info">{t('identityGate.body')}</Alert>
        {device && (
          <Button variant="secondary" size="lg" block icon="fingerprint" disabled={busy} onClick={() => void finish({ device: true })}>
            {t('identityGate.useDevice')}
          </Button>
        )}
        <PasswordInput
          label={device ? t('identityGate.passwordOrDevice') : t('fields.masterPassword')}
          autoComplete="current-password"
          autoFocus
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          error={error}
        />
        <Button type="submit" size="lg" block busy={busy} disabled={!password}>
          {t('identityGate.confirm')}
        </Button>
        <Button variant="ghost" onClick={cancel}>
          {t('common.cancel')}
        </Button>
      </form>
    </AuthLayout>
  );
}
