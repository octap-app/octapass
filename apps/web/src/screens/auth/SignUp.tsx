import { Button, Checkbox, Icon, TextField } from '@octapass/ui';
import { isValidEmail, isVaultError, normalizeEmail, VaultError, type RecoveryKit } from '@octapass/vault-client';
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
import styles from './SignUp.module.css';

type Step = 'account' | 'verify' | 'kit' | 'done';
const STEPS: Step[] = ['account', 'verify', 'kit', 'done'];

/** A master password must reach "strong" (score 3): the Secret Key protects the server copy, this protects the device. */
export const MIN_SCORE = 3;

function Progress({ step }: { step: Step }) {
  const index = STEPS.indexOf(step);
  return (
    <div className={styles.progress}>
      <p className="visually-hidden">{t('signUp.stepOf', { step: index + 1, total: STEPS.length })}</p>
      <ol aria-hidden="true">
        {STEPS.map((s, i) => (
          <li key={s} className={i < index ? styles.done : i === index ? styles.current : undefined} />
        ))}
      </ol>
    </div>
  );
}

export function SignUp() {
  const session = useSession();
  const [step, setStep] = useState<Step>('account');
  const [signup, setSignup] = useState<{ id: string; email: string; devCode?: string }>();
  const [kit, setKit] = useState<RecoveryKit>();
  const heading = useRef<HTMLDivElement>(null);

  // Move focus to the new step so screen reader and keyboard users start at its top.
  useEffect(() => {
    if (step !== 'account') heading.current?.querySelector('h1')?.focus();
  }, [step]);

  if (step === 'account' && session.status !== 'signedOut') return <Navigate to="/" replace />;

  return (
    <div ref={heading}>
      {step === 'account' && (
        <AccountStep
          onDone={(id, email, devCode) => {
            setSignup({ id, email, devCode });
            setStep('verify');
          }}
        />
      )}
      {step === 'verify' && signup && (
        <VerifyStep
          signup={signup}
          onBack={() => setStep('account')}
          onDone={(recoveryKit) => {
            setKit(recoveryKit);
            setStep('kit');
          }}
        />
      )}
      {step === 'kit' && kit && <KitStep kit={kit} onDone={() => setStep('done')} />}
      {step === 'done' && <DoneStep />}
    </div>
  );
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
    if (Object.keys(next).length) {
      document.querySelector<HTMLElement>('[aria-invalid="true"]')?.focus();
      return;
    }
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
    <AuthLayout
      top={<Progress step="account" />}
      title={t('signUp.title')}
      subtitle={t('signUp.subtitle')}
      footer={
        <>
          {t('signUp.haveAccount')} <Link to="/welcome">{t('signUp.signIn')}</Link>
        </>
      }
    >
      <form className={styles.form} onSubmit={submit} noValidate>
        {formError && <Alert>{formError}</Alert>}
        <TextField label={t('fields.email')} type="email" inputMode="email" autoComplete="email" autoFocus value={email} onChange={(e) => setEmail(e.target.value)} error={errors.email} />
        <div className={styles.passwordGroup}>
          <PasswordInput
            label={t('fields.masterPassword')}
            autoComplete="new-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            error={errors.password}
          />
          <StrengthHint estimate={estimate} empty={!password} />
        </div>
        <PasswordInput label={t('fields.confirmPassword')} autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} error={errors.confirm} />
        <div className={styles.guidance}>
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

function VerifyStep({ signup, onBack, onDone }: { signup: { id: string; email: string; devCode?: string }; onBack: () => void; onDone: (kit: RecoveryKit) => void }) {
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
      const { recoveryKit } = await service.finishSignup({ signupId: signup.id, verificationCode: code });
      onDone(recoveryKit);
    } catch (e) {
      setError(errorMessage(e));
      setBusy(false);
    }
  }

  return (
    <AuthLayout top={<Progress step="verify" />} title={t('verify.title')} subtitle={t('verify.subtitle', { email: signup.email })}>
      <form className={styles.form} onSubmit={submit} noValidate>
        {signup.devCode && (
          <Alert tone="info">
            {t('verify.devCode')} <strong className="mono">{signup.devCode}</strong>
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
          {t('verify.submit')}
        </Button>
        <Button variant="ghost" onClick={onBack}>
          {t('verify.changeEmail')}
        </Button>
      </form>
    </AuthLayout>
  );
}

function KitStep({ kit, onDone }: { kit: RecoveryKit; onDone: () => void }) {
  const [saved, setSaved] = useState(false);
  return (
    <AuthLayout wide top={<Progress step="kit" />} title={t('kit.title')} subtitle={t('kit.subtitle')}>
      <RecoveryKitSheet kit={kit} />
      <Button variant="secondary" icon="printer" size="lg" block onClick={() => window.print()}>
        {t('kit.print')}
      </Button>
      <div className={styles.confirm}>
        <Checkbox label={t('kit.confirm')} checked={saved} onChange={(e) => setSaved(e.target.checked)} />
      </div>
      <Button size="lg" block disabled={!saved} onClick={onDone}>
        {t('kit.continue')}
      </Button>
    </AuthLayout>
  );
}

function DoneStep() {
  const navigate = useNavigate();
  return (
    <AuthLayout top={<Progress step="done" />} title={t('done.title')} subtitle={t('done.subtitle')}>
      <ul className={styles.facts}>
        <li>
          <Icon name="lock" size={18} />
          {t('done.fact1')}
        </li>
        <li>
          <Icon name="key" size={18} />
          {t('done.fact2')}
        </li>
        <li>
          <Icon name="shield" size={18} />
          {t('done.fact3')}
        </li>
      </ul>
      <Button size="lg" block autoFocus onClick={() => navigate('/items/all', { replace: true })}>
        {t('done.open')}
      </Button>
    </AuthLayout>
  );
}
