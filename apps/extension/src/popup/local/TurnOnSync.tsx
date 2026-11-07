import { Button, Checkbox, Icon, TextField } from '@octapass/ui';
import { isValidEmail, isVaultError, normalizeEmail, VaultError, type RecoveryKit } from '@octapass/vault-client';
import { useService, useSession } from '@octapass/web/src/app/ServiceContext';
import { Alert } from '@octapass/web/src/components/Alert';
import { PasswordInput } from '@octapass/web/src/components/PasswordInput';
import { StrengthHint } from '@octapass/web/src/components/StrengthHint';
import { t } from '@octapass/web/src/i18n';
import { errorMessage } from '@octapass/web/src/lib/errors';
import { AuthLayout } from '@octapass/web/src/screens/auth/AuthLayout';
import { RecoveryKitSheet } from '@octapass/web/src/screens/auth/RecoveryKitSheet';
import { HOSTED, ServerPicker, serverUrlOf, type ServerChoice } from '@octapass/web/src/screens/auth/ServerPicker';
import signUp from '@octapass/web/src/screens/auth/SignUp.module.css';
import { useState, type FormEvent } from 'react';
import { Navigate, useNavigate } from 'react-router';
import { tx } from '../../i18n';
import { LOCAL_SERVER } from '../../shared/local';

const MIN_SCORE = 3;

/**
 * Turn on sync: the sign-up steps, but the service worker keeps this vault's keys and items
 * (`LocalVault.upgradeToAccount`) and moves them into the new account once the email is verified.
 */
export function TurnOnSync() {
  const session = useSession();
  // Only for a local vault; once it moves into the account, the Recovery Kit still shows.
  const [local] = useState(session.serverUrl === LOCAL_SERVER);
  const [pending, setPending] = useState<{ id: string; email: string; devCode?: string }>();
  const [kit, setKit] = useState<RecoveryKit>();
  if (kit) return <KitStep kit={kit} />;
  if (!local) return <Navigate to="/" replace />;
  if (pending) return <VerifyStep pending={pending} onBack={() => setPending(undefined)} onDone={setKit} />;
  return <AccountStep onDone={(id, email, devCode) => setPending({ id, email, ...(devCode ? { devCode } : {}) })} />;
}

function AccountStep({ onDone }: { onDone: (signupId: string, email: string, devCode?: string) => void }) {
  const service = useService();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [server, setServer] = useState<ServerChoice>(HOSTED);
  const [errors, setErrors] = useState<{ email?: string; password?: string; confirm?: string; server?: string }>({});
  const [formError, setFormError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const estimate = service.estimateStrength(password);

  async function submit(event: FormEvent) {
    event.preventDefault();
    const next: typeof errors = {};
    if (!isValidEmail(normalizeEmail(email))) next.email = t('validation.email');
    if (estimate.score < MIN_SCORE) next.password = password ? t('validation.passwordTooWeak') : t('validation.passwordRequired');
    if (confirm !== password) next.confirm = t('validation.passwordsDontMatch');
    setErrors(next);
    setFormError(undefined);
    if (Object.keys(next).length) return;
    setBusy(true);
    try {
      const serverUrl = serverUrlOf(server);
      const info = await service.getServerInfo(serverUrl);
      if (info.signups === 'closed') throw new VaultError('signupsClosed');
      const { signupId, devVerificationCode } = await service.startSignup({ serverUrl, email, password });
      onDone(signupId, normalizeEmail(email), devVerificationCode);
    } catch (error) {
      if (server.kind === 'self' && (isVaultError(error, 'insecureServerUrl') || isVaultError(error, 'serverUnreachable'))) setErrors({ server: errorMessage(error) });
      else setFormError(errorMessage(error));
      setBusy(false);
    }
  }

  return (
    <AuthLayout title={tx('local.syncTitle')} subtitle={tx('local.syncSubtitle')}>
      <form className={signUp.form} onSubmit={submit} noValidate>
        {formError && <Alert>{formError}</Alert>}
        <TextField label={t('fields.email')} type="email" inputMode="email" autoComplete="email" autoFocus value={email} onChange={(e) => setEmail(e.target.value)} error={errors.email} />
        <div className={signUp.passwordGroup}>
          <PasswordInput label={t('fields.masterPassword')} autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} error={errors.password} />
          <StrengthHint estimate={estimate} empty={!password} />
        </div>
        <PasswordInput label={t('fields.confirmPassword')} autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} error={errors.confirm} />
        <div className={signUp.guidance}>
          <Icon name="info" size={18} />
          <p>{t('signUp.guidance')}</p>
        </div>
        <ServerPicker value={server} onChange={setServer} error={errors.server} />
        <Button type="submit" size="lg" block busy={busy}>
          {t('signUp.continue')}
        </Button>
      </form>
    </AuthLayout>
  );
}

function VerifyStep({ pending, onBack, onDone }: { pending: { id: string; email: string; devCode?: string }; onBack: () => void; onDone: (kit: RecoveryKit) => void }) {
  const service = useService();
  const [code, setCode] = useState('');
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!/^\d{6}$/.test(code.replace(/\s/g, ''))) return setError(t('validation.code'));
    setBusy(true);
    setError(undefined);
    try {
      onDone((await service.finishSignup({ signupId: pending.id, verificationCode: code })).recoveryKit);
    } catch (e) {
      setError(errorMessage(e));
      setBusy(false);
    }
  }

  return (
    <AuthLayout title={t('verify.title')} subtitle={t('verify.subtitle', { email: pending.email })}>
      <form className={signUp.form} onSubmit={submit} noValidate>
        {pending.devCode && (
          <Alert tone="info">
            {t('verify.devCode')} <strong className="mono">{pending.devCode}</strong>
          </Alert>
        )}
        <TextField label={t('verify.codeLabel')} inputMode="numeric" autoComplete="one-time-code" maxLength={7} mono autoFocus value={code} onChange={(e) => setCode(e.target.value.replace(/[^\d ]/g, ''))} error={error} />
        <Button type="submit" size="lg" block busy={busy}>
          {t('verify.submit')}
        </Button>
        <Button variant="ghost" onClick={onBack}>
          {t('verify.changeEmail')}
        </Button>
      </form>
    </AuthLayout>
  );
}

function KitStep({ kit }: { kit: RecoveryKit }) {
  const navigate = useNavigate();
  const [saved, setSaved] = useState(false);
  return (
    <AuthLayout wide title={tx('local.syncDoneTitle')} subtitle={`${tx('local.syncDoneSubtitle')} ${t('kit.subtitle')}`}>
      <RecoveryKitSheet kit={kit} />
      <Button variant="secondary" icon="printer" size="lg" block onClick={() => window.print()}>
        {t('kit.print')}
      </Button>
      <div className={signUp.confirm}>
        <Checkbox label={t('kit.confirm')} checked={saved} onChange={(e) => setSaved(e.target.checked)} />
      </div>
      <Button size="lg" block disabled={!saved} onClick={() => navigate('/', { replace: true })}>
        {t('kit.continue')}
      </Button>
    </AuthLayout>
  );
}
