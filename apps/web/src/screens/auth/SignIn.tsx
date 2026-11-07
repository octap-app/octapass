import { isValidEmail, normalizeEmail, parseSecretKey, VaultError, type SignInResult, type SsoRequired, type TwoStepMethod } from '@octapass/vault-client';
import { Button, TextField } from '@octapass/ui';
import { useEffect, useState, type FormEvent } from 'react';
import { Link } from 'react-router';
import { useService } from '../../app/ServiceContext';
import { Alert } from '../../components/Alert';
import { PasswordInput } from '../../components/PasswordInput';
import { t } from '../../i18n';
import { errorMessage } from '../../lib/errors';
import { LocalChoices } from '../local/LocalChoices';
import { AuthLayout } from './AuthLayout';
import { HOSTED, ServerPicker, serverUrlOf, type ServerChoice } from './ServerPicker';
import styles from './SignIn.module.css';
import { SsoStep } from './SsoStep';
import { TwoStepForm } from './TwoStepForm';

interface FieldErrors {
  email?: string;
  password?: string;
  secretKey?: string;
  server?: string;
}

export function SignIn() {
  const service = useService();
  const remembered = service.rememberedAccounts();
  const [email, setEmail] = useState(remembered[0]?.email ?? '');
  const [password, setPassword] = useState('');
  const [secretKey, setSecretKey] = useState('');
  const [server, setServer] = useState<ServerChoice>(
    remembered[0] && remembered[0].serverUrl !== HOSTED.url ? { kind: 'self', url: remembered[0].serverUrl } : HOSTED,
  );
  const [showServer, setShowServer] = useState(server.kind === 'self');
  const [errors, setErrors] = useState<FieldErrors>({});
  const [formError, setFormError] = useState<string>();
  const [busy, setBusy] = useState(false);
  /** The account asked for a second step, with these ways to give it. */
  const [twoStep, setTwoStep] = useState<TwoStepMethod[]>();
  /** The account's organisation asks for its identity provider, before any second step. */
  const [sso, setSso] = useState<SsoRequired>();
  // The extension popup closes while the user reads a code; it reopens onto the waiting second step.
  const [checking, setChecking] = useState(Boolean(service.pendingTwoStep));

  useEffect(() => {
    if (!service.pendingTwoStep) return;
    let live = true;
    service
      .pendingTwoStep()
      .then(
        (waiting) => {
          if (!live) return;
          if (waiting?.status === 'twoStepRequired') setTwoStep(waiting.methods);
          if (waiting?.status === 'ssoRequired') setSso(waiting);
          if (waiting?.status === 'twoStepExpired') {
            setFormError(errorMessage(new VaultError('twoStepExpired')));
            void service.cancelTwoStep?.().catch(() => undefined);
          }
        },
        () => undefined,
      )
      .finally(() => live && setChecking(false));
    return () => {
      live = false;
    };
  }, [service]);

  // The Secret Key lives on each signed-in device. Ask for it only where this account isn't known yet.
  const knownDevice = remembered.some((a) => a.email === normalizeEmail(email) && a.serverUrl === serverUrlOf(server));
  // A rotation elsewhere leaves this device with an old one, so a known device can still type it.
  const [replaceSecretKey, setReplaceSecretKey] = useState(false);
  const needsSecretKey = !knownDevice || replaceSecretKey;

  function validate(): FieldErrors {
    const next: FieldErrors = {};
    if (!isValidEmail(normalizeEmail(email))) next.email = t('validation.email');
    if (!password) next.password = t('validation.passwordRequired');
    if (needsSecretKey && !parseSecretKey(secretKey)) next.secretKey = secretKey.trim() ? t('errors.invalidSecretKey') : t('validation.secretKeyRequired');
    if (server.kind === 'self' && !/^https:\/\/.+/i.test(server.url.trim()) && !/^http:\/\/(localhost|127\.0\.0\.1)/i.test(server.url.trim())) {
      next.server = t('errors.insecureServerUrl');
    }
    return next;
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    const fieldErrors = validate();
    setErrors(fieldErrors);
    setFormError(undefined);
    if (Object.keys(fieldErrors).length) {
      document.querySelector<HTMLElement>('[aria-invalid="true"]')?.focus();
      return;
    }
    setBusy(true);
    try {
      const serverUrl = serverUrlOf(server);
      if (server.kind === 'self') await service.getServerInfo(serverUrl);
      const result = await service.signIn({ serverUrl, email, password, secretKey: needsSecretKey ? secretKey : undefined });
      if (result.status !== 'signedIn') {
        setPassword('');
        setBusy(false);
        nextStep(result);
      }
    } catch (error) {
      setFormError(errorMessage(error));
      setBusy(false);
    }
  }

  function nextStep(result: SignInResult) {
    setSso(result.status === 'ssoRequired' ? result : undefined);
    if (result.status === 'twoStepRequired') setTwoStep(result.methods);
  }

  if (checking) return null;
  if (sso) {
    return (
      <SsoStep
        sso={sso}
        onNext={nextStep}
        onStartOver={(error) => {
          void service.cancelTwoStep?.().catch(() => undefined);
          setSso(undefined);
          setFormError(error);
        }}
      />
    );
  }
  if (twoStep) {
    return (
      <TwoStepForm
        methods={twoStep}
        onStartOver={(error) => {
          void service.cancelTwoStep?.().catch(() => undefined);
          setTwoStep(undefined);
          setFormError(error);
        }}
      />
    );
  }

  return (
    <AuthLayout
      title={t('signIn.title')}
      subtitle={t('signIn.subtitle')}
      footer={
        <>
          {t('signIn.noAccount')} <Link to="/signup">{t('signIn.createAccount')}</Link>
        </>
      }
    >
      <form className={styles.form} onSubmit={submit} noValidate>
        {formError && <Alert>{formError}</Alert>}
        <TextField
          label={t('fields.email')}
          type="email"
          autoComplete="username"
          inputMode="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          error={errors.email}
          autoFocus={!email}
        />
        <PasswordInput
          label={t('fields.masterPassword')}
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          error={errors.password}
          autoFocus={Boolean(email)}
        />
        {service.startPasswordReset && (
          <p className={styles.forgot}>
            <Link to="/reset">{t('signIn.forgotPassword')}</Link>
          </p>
        )}
        {knownDevice && !replaceSecretKey && (
          <p className={styles.forgot}>
            <button type="button" className={styles.link} onClick={() => setReplaceSecretKey(true)}>
              {t('signIn.newSecretKey')}
            </button>
          </p>
        )}
        {needsSecretKey && (
          <TextField
            label={t('fields.secretKey')}
            mono
            spellCheck={false}
            autoCapitalize="characters"
            autoComplete="off"
            placeholder="OP1-XXXXXX-XXXXXX-XXXXX-XXXXX-XXXX"
            value={secretKey}
            onChange={(e) => setSecretKey(e.target.value)}
            hint={t('signIn.secretKeyHint')}
            error={errors.secretKey}
          />
        )}
        {showServer ? (
          <ServerPicker value={server} onChange={setServer} error={errors.server} />
        ) : (
          <p className={styles.server}>
            {t('signIn.signingInTo', { server: t('server.hosted') })}{' '}
            <button type="button" className={styles.link} onClick={() => setShowServer(true)}>
              {t('signIn.changeServer')}
            </button>
          </p>
        )}
        <Button type="submit" size="lg" block busy={busy}>
          {t('signIn.submit')}
        </Button>
      </form>
      <LocalChoices />
    </AuthLayout>
  );
}
