import { Button, Checkbox, Icon, TextField } from '@octapass/ui';
import { isValidEmail, isVaultError, normalizeEmail, type RecoveryKit, type TwoStepMethod } from '@octapass/vault-client';
import { useEffect, useRef, useState, type FormEvent } from 'react';
import { Link, Navigate, useNavigate } from 'react-router';
import { useService, useSession } from '../../app/ServiceContext';
import { Alert } from '../../components/Alert';
import { PasswordInput } from '../../components/PasswordInput';
import { StrengthHint } from '../../components/StrengthHint';
import { t } from '../../i18n';
import { errorMessage } from '../../lib/errors';
import { AuthLayout } from './AuthLayout';
import { RecoveryKitSheet } from './RecoveryKitSheet';
import { HOSTED, ServerPicker, serverUrlOf, type ServerChoice } from './ServerPicker';
import { MIN_SCORE } from './SignUp';
import styles from './SignUp.module.css';
import { TwoStepForm } from './TwoStepForm';

interface Reset {
  id: string;
  email: string;
  devCode?: string;
}

type Step = { name: 'email' } | { name: 'verify'; reset: Reset } | { name: 'password'; reset: Reset } | { name: 'kit'; kit: RecoveryKit; next: After } | { name: 'twoStep'; methods: TwoStepMethod[] };

/** Where the reset goes after the new Recovery Kit is saved. */
type After = { signedIn: true } | { signedIn: false; methods?: TwoStepMethod[] };

/**
 * "Forgot master password?" (plan 03, Recovery): a code to the account's email, then the recovery
 * code from the Recovery Kit and a new master password. The recovery code is replaced, so the
 * last step is a new Recovery Kit.
 */
export function ResetPassword() {
  const service = useService();
  const session = useSession();
  const navigate = useNavigate();
  const [step, setStep] = useState<Step>({ name: 'email' });
  const [startError, setStartError] = useState<string>();
  const top = useRef<HTMLDivElement>(null);

  // Move focus to the new step so screen reader and keyboard users start at its top.
  useEffect(() => {
    if (step.name !== 'email') top.current?.querySelector('h1')?.focus();
  }, [step.name]);

  // The second step finished signing in.
  useEffect(() => {
    if (step.name === 'twoStep' && session.status === 'unlocked') navigate('/items/all', { replace: true });
  }, [step.name, session.status, navigate]);

  if (!service.startPasswordReset) return <Navigate to="/welcome" replace />;
  if (step.name === 'email' && session.status === 'unlocked') return <Navigate to="/" replace />;

  function startOver(error?: string) {
    if ('reset' in step) void service.cancelPasswordReset?.(step.reset.id).catch(() => undefined);
    setStartError(error);
    setStep({ name: 'email' });
  }

  function afterKit(next: After) {
    if (next.signedIn) navigate('/items/all', { replace: true });
    else if (next.methods) setStep({ name: 'twoStep', methods: next.methods });
    else navigate('/welcome', { replace: true });
  }

  return (
    <div ref={top}>
      {step.name === 'email' && <EmailStep error={startError} onDone={(reset) => setStep({ name: 'verify', reset })} />}
      {step.name === 'verify' && <VerifyStep reset={step.reset} onBack={() => startOver()} onExpired={startOver} onDone={() => setStep({ name: 'password', reset: step.reset })} />}
      {step.name === 'password' && <PasswordStep reset={step.reset} onExpired={startOver} onDone={(kit, next) => setStep({ name: 'kit', kit, next })} />}
      {step.name === 'kit' && <KitStep kit={step.kit} onDone={() => afterKit(step.next)} />}
      {step.name === 'twoStep' && (
        <TwoStepForm
          methods={step.methods}
          onStartOver={() => {
            void service.cancelTwoStep?.().catch(() => undefined);
            navigate('/welcome', { replace: true });
          }}
        />
      )}
    </div>
  );
}

function EmailStep({ error, onDone }: { error?: string; onDone: (reset: Reset) => void }) {
  const service = useService();
  const session = useSession();
  const remembered = service.rememberedAccounts();
  const known = session.email && session.serverUrl ? { email: session.email, serverUrl: session.serverUrl } : remembered[0];
  const [email, setEmail] = useState(known?.email ?? '');
  const [server, setServer] = useState<ServerChoice>(known && known.serverUrl !== HOSTED.url ? { kind: 'self', url: known.serverUrl } : HOSTED);
  const [showServer, setShowServer] = useState(server.kind === 'self');
  const [errors, setErrors] = useState<{ email?: string; server?: string }>({});
  const [formError, setFormError] = useState(error);
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setFormError(undefined);
    if (!isValidEmail(normalizeEmail(email))) {
      setErrors({ email: t('validation.email') });
      return;
    }
    setErrors({});
    setBusy(true);
    try {
      const serverUrl = serverUrlOf(server);
      if (server.kind === 'self') await service.getServerInfo(serverUrl);
      const { resetId, devVerificationCode } = await service.startPasswordReset!({ serverUrl, email });
      onDone({ id: resetId, email: normalizeEmail(email), ...(devVerificationCode ? { devCode: devVerificationCode } : {}) });
    } catch (e) {
      if (server.kind === 'self' && (isVaultError(e, 'insecureServerUrl') || isVaultError(e, 'serverUnreachable'))) setErrors({ server: errorMessage(e) });
      else setFormError(errorMessage(e));
      setBusy(false);
    }
  }

  return (
    <AuthLayout
      title={t('reset.title')}
      subtitle={t('reset.subtitle')}
      footer={
        <>
          {t('reset.remembered')} <Link to={session.status === 'locked' ? '/lock' : '/welcome'}>{t('reset.back')}</Link>
        </>
      }
    >
      <form className={styles.form} onSubmit={submit} noValidate>
        {formError && <Alert>{formError}</Alert>}
        <TextField
          label={t('fields.email')}
          type="email"
          inputMode="email"
          autoComplete="username"
          autoFocus
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          error={errors.email}
        />
        <div className={styles.guidance}>
          <Icon name="info" size={18} />
          <p>{t('reset.needs')}</p>
        </div>
        {showServer ? (
          <ServerPicker value={server} onChange={setServer} error={errors.server} />
        ) : (
          <Button variant="ghost" onClick={() => setShowServer(true)}>
            {t('signIn.changeServer')}
          </Button>
        )}
        <Button type="submit" size="lg" block busy={busy}>
          {t('reset.sendCode')}
        </Button>
      </form>
    </AuthLayout>
  );
}

function VerifyStep({ reset, onBack, onExpired, onDone }: { reset: Reset; onBack: () => void; onExpired: (error: string) => void; onDone: () => void }) {
  const service = useService();
  const [code, setCode] = useState('');
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!/^\d{6}$/.test(code.replace(/\s/g, ''))) {
      setError(t('validation.code'));
      return;
    }
    setBusy(true);
    setError(undefined);
    try {
      await service.verifyPasswordReset!({ resetId: reset.id, verificationCode: code });
      onDone();
    } catch (e) {
      if (isVaultError(e, 'resetExpired')) return onExpired(errorMessage(e));
      setError(errorMessage(e));
      setBusy(false);
    }
  }

  return (
    <AuthLayout title={t('verify.title')} subtitle={t('reset.codeSent', { email: reset.email })}>
      <form className={styles.form} onSubmit={submit} noValidate>
        {reset.devCode && (
          <Alert tone="info">
            {t('verify.devCode')} <strong className="mono">{reset.devCode}</strong>
          </Alert>
        )}
        <TextField
          label={t('verify.codeLabel')}
          inputMode="numeric"
          autoComplete="one-time-code"
          maxLength={7}
          mono
          className={styles.code}
          autoFocus
          value={code}
          onChange={(e) => setCode(e.target.value.replace(/[^\d ]/g, ''))}
          error={error}
        />
        <Button type="submit" size="lg" block busy={busy}>
          {t('reset.verify')}
        </Button>
        <Button variant="ghost" onClick={onBack}>
          {t('verify.changeEmail')}
        </Button>
      </form>
    </AuthLayout>
  );
}

function PasswordStep({ reset, onExpired, onDone }: { reset: Reset; onExpired: (error: string) => void; onDone: (kit: RecoveryKit, next: After) => void }) {
  const service = useService();
  const [recoveryCode, setRecoveryCode] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [errors, setErrors] = useState<{ recoveryCode?: string; password?: string; confirm?: string }>({});
  const [formError, setFormError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const estimate = service.estimateStrength(password);

  async function submit(event: FormEvent) {
    event.preventDefault();
    const next: typeof errors = {};
    if (!recoveryCode.trim()) next.recoveryCode = t('reset.recoveryCodeRequired');
    if (estimate.score < MIN_SCORE) next.password = password ? t('validation.passwordTooWeak') : t('validation.passwordRequired');
    if (confirm !== password) next.confirm = t('validation.passwordsDontMatch');
    setErrors(next);
    setFormError(undefined);
    if (Object.keys(next).length) {
      document.querySelector<HTMLElement>('[aria-invalid="true"]')?.focus();
      return;
    }
    setBusy(true);
    try {
      const { recoveryKit, signIn } = await service.finishPasswordReset!({ resetId: reset.id, recoveryCode, password });
      // An SSO step waits in the service: the sign-in screen picks it up from there.
      onDone(recoveryKit, signIn?.status === 'signedIn' ? { signedIn: true } : { signedIn: false, ...(signIn?.status === 'twoStepRequired' ? { methods: signIn.methods } : {}) });
    } catch (e) {
      if (isVaultError(e, 'resetExpired')) return onExpired(errorMessage(e));
      if (isVaultError(e, 'invalidRecoveryCode')) setErrors({ recoveryCode: errorMessage(e) });
      else setFormError(errorMessage(e));
      setBusy(false);
    }
  }

  return (
    <AuthLayout title={t('reset.passwordTitle')} subtitle={t('reset.passwordSubtitle')}>
      <form className={styles.form} onSubmit={submit} noValidate>
        {formError && <Alert>{formError}</Alert>}
        {/* A hidden username lets password managers pair the new password with the account. */}
        <input type="email" name="username" autoComplete="username" value={reset.email} readOnly hidden />
        <TextField
          label={t('kit.recoveryCode')}
          mono
          spellCheck={false}
          autoCapitalize="characters"
          autoComplete="off"
          autoFocus
          value={recoveryCode}
          onChange={(e) => setRecoveryCode(e.target.value)}
          hint={t('reset.recoveryCodeHint')}
          error={errors.recoveryCode}
        />
        <div className={styles.passwordGroup}>
          <PasswordInput label={t('reset.newPassword')} autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} error={errors.password} />
          <StrengthHint estimate={estimate} empty={!password} />
        </div>
        <PasswordInput label={t('fields.confirmPassword')} autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} error={errors.confirm} />
        <div className={styles.guidance}>
          <Icon name="info" size={18} />
          <p>{t('reset.signsOut')}</p>
        </div>
        <Button type="submit" size="lg" block busy={busy}>
          {t('reset.submit')}
        </Button>
      </form>
    </AuthLayout>
  );
}

function KitStep({ kit, onDone }: { kit: RecoveryKit; onDone: () => void }) {
  const [saved, setSaved] = useState(false);
  return (
    <AuthLayout wide title={t('reset.kitTitle')} subtitle={t('reset.kitSubtitle')}>
      <RecoveryKitSheet kit={kit} />
      <Button variant="secondary" icon="printer" size="lg" block onClick={() => window.print()}>
        {t('kit.print')}
      </Button>
      <div className={styles.confirm}>
        <Checkbox label={t('reset.kitConfirm')} checked={saved} onChange={(e) => setSaved(e.target.checked)} />
      </div>
      <Button size="lg" block disabled={!saved} onClick={onDone}>
        {t('kit.continue')}
      </Button>
    </AuthLayout>
  );
}
