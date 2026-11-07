import { Button, Checkbox, Icon } from '@octapass/ui';
import { useService, useSession } from '@octapass/web/src/app/ServiceContext';
import { Alert } from '@octapass/web/src/components/Alert';
import { PasswordInput } from '@octapass/web/src/components/PasswordInput';
import { StrengthHint } from '@octapass/web/src/components/StrengthHint';
import { t } from '@octapass/web/src/i18n';
import { errorMessage } from '@octapass/web/src/lib/errors';
import { AuthLayout } from '@octapass/web/src/screens/auth/AuthLayout';
import signUp from '@octapass/web/src/screens/auth/SignUp.module.css';
import { useState, type FormEvent } from 'react';
import { Navigate, useNavigate } from 'react-router';
import { tx } from '../../i18n';
import { useExtension } from '../ExtensionContext';
import { RecoveryCode } from './RecoveryCode';

/** The core refuses master passwords below this zxcvbn score for vaults without a hardware secret. */
const MIN_SCORE = 4;

/** "Use on this device only": a master password, then the backup recovery code. */
export function CreateLocal() {
  const session = useSession();
  const [code, setCode] = useState<string>();
  if (code) return <LocalKit code={code} />;
  // Creating unlocks the new vault, so this screen guards itself rather than through RequireSignedOut.
  if (session.status !== 'signedOut') return <Navigate to="/" replace />;
  return <PasswordStep onCreated={setCode} />;
}

function PasswordStep({ onCreated }: { onCreated: (code: string) => void }) {
  const service = useService();
  const { api } = useExtension();
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [errors, setErrors] = useState<{ password?: string; confirm?: string }>({});
  const [formError, setFormError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const estimate = service.estimateStrength(password);

  async function submit(event: FormEvent) {
    event.preventDefault();
    const next: typeof errors = {};
    if (estimate.score < MIN_SCORE) next.password = password ? tx('local.weak') : t('validation.passwordRequired');
    if (confirm !== password) next.confirm = t('validation.passwordsDontMatch');
    setErrors(next);
    setFormError(undefined);
    if (Object.keys(next).length) return;
    setBusy(true);
    try {
      onCreated(await api.createLocalVault(password));
    } catch (e) {
      if (e instanceof Error && e.message === 'weak_master_password') setErrors({ password: tx('local.weak') });
      else setFormError(errorMessage(e));
      setBusy(false);
    }
  }

  return (
    <AuthLayout title={tx('local.createTitle')} subtitle={tx('local.createSubtitle')}>
      <form className={signUp.form} onSubmit={submit} noValidate>
        {formError && <Alert>{formError}</Alert>}
        <div className={signUp.passwordGroup}>
          <PasswordInput label={t('fields.masterPassword')} autoComplete="new-password" autoFocus value={password} onChange={(e) => setPassword(e.target.value)} error={errors.password} />
          <StrengthHint estimate={estimate} empty={!password} />
        </div>
        <PasswordInput label={t('fields.confirmPassword')} autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} error={errors.confirm} />
        <div className={signUp.guidance}>
          <Icon name="info" size={18} />
          <p>{tx('local.guidance')}</p>
        </div>
        <Button type="submit" size="lg" block busy={busy}>
          {busy ? tx('local.creating') : tx('local.create')}
        </Button>
      </form>
    </AuthLayout>
  );
}

function LocalKit({ code }: { code: string }) {
  const navigate = useNavigate();
  const [saved, setSaved] = useState(false);
  return (
    <AuthLayout title={tx('local.kitTitle')} subtitle={tx('local.kitSubtitle')}>
      <RecoveryCode code={code} />
      <div className={signUp.confirm}>
        <Checkbox label={tx('local.kitConfirm')} checked={saved} onChange={(e) => setSaved(e.target.checked)} />
      </div>
      <Button size="lg" block disabled={!saved} onClick={() => navigate('/', { replace: true })}>
        {tx('local.kitContinue')}
      </Button>
    </AuthLayout>
  );
}
