import { isVaultError, type TwoStepMethod, type TwoStepProof } from '@octapass/vault-client';
import { Button, TextField } from '@octapass/ui';
import { useState, type FormEvent } from 'react';
import { useService } from '../../app/ServiceContext';
import { Alert } from '../../components/Alert';
import { t, type MessageKey } from '../../i18n';
import { errorMessage } from '../../lib/errors';
import { AuthLayout } from './AuthLayout';
import styles from './SignIn.module.css';

const SUBTITLES: Record<TwoStepMethod, MessageKey> = {
  totp: 'twoStep.totpSubtitle',
  securityKey: 'twoStep.securityKeySubtitle',
  recoveryCode: 'twoStep.recoverySubtitle',
};

const SWITCH_TO: Record<TwoStepMethod, MessageKey> = {
  totp: 'twoStep.useCode',
  securityKey: 'twoStep.useSecurityKey',
  recoveryCode: 'twoStep.useRecovery',
};

/**
 * The second step of signing in on a new device, when the account has two-step sign-in on (plan 03,
 * "Account 2FA"). `methods` holds only what this app can do. `onStartOver` goes back to the password,
 * with an error to show when the sign-in ran out of time or tries.
 */
export function TwoStepForm({ methods, onStartOver }: { methods: TwoStepMethod[]; onStartOver: (error?: string) => void }) {
  const service = useService();
  const [method, setMethod] = useState<TwoStepMethod>(methods.includes('totp') ? 'totp' : methods[0]!);
  const [code, setCode] = useState('');
  const [fieldError, setFieldError] = useState<string>();
  const [formError, setFormError] = useState<string>();
  const [busy, setBusy] = useState(false);

  async function finish(proof: TwoStepProof) {
    setBusy(true);
    setFieldError(undefined);
    setFormError(undefined);
    try {
      // Signed in: the route guards take it from here.
      await service.finishTwoStep(proof);
    } catch (error) {
      setBusy(false);
      if (isVaultError(error, 'twoStepExpired')) {
        onStartOver(errorMessage(error));
      } else if (isVaultError(error, 'invalidTwoStepCode') && proof.method !== 'securityKey') {
        setFieldError(errorMessage(error));
        setCode('');
        document.querySelector<HTMLInputElement>('#two-step-code')?.focus();
      } else {
        setFormError(errorMessage(error));
      }
    }
  }

  function choose(next: TwoStepMethod) {
    setMethod(next);
    setCode('');
    setFieldError(undefined);
    setFormError(undefined);
    // Straight from the click: some browsers only show the security key prompt during a user action.
    if (next === 'securityKey') void finish({ method: 'securityKey' });
  }

  function submit(event: FormEvent) {
    event.preventDefault();
    if (method === 'securityKey') return void finish({ method: 'securityKey' });
    const typed = method === 'totp' ? code.replace(/\s/g, '') : code.trim();
    if (method === 'totp' && !/^\d{6}$/.test(typed)) return setFieldError(t('twoStep.codeRequired'));
    if (method === 'recoveryCode' && !typed) return setFieldError(t('twoStep.recoveryRequired'));
    void finish({ method, code: typed });
  }

  return (
    <AuthLayout
      title={t('twoStep.title')}
      subtitle={t(SUBTITLES[method])}
      footer={
        <button type="button" className={styles.link} onClick={() => onStartOver()} disabled={busy}>
          {t('twoStep.startOver')}
        </button>
      }
    >
      <form className={styles.form} onSubmit={submit} noValidate>
        {formError && <Alert>{formError}</Alert>}
        {method === 'totp' && (
          <TextField
            key="totp"
            id="two-step-code"
            label={t('twoStep.codeLabel')}
            mono
            autoComplete="one-time-code"
            inputMode="numeric"
            pattern="[0-9 ]*"
            maxLength={7}
            autoFocus
            value={code}
            onChange={(e) => setCode(e.target.value)}
            error={fieldError}
          />
        )}
        {method === 'recoveryCode' && (
          <TextField
            key="recovery"
            id="two-step-code"
            label={t('twoStep.recoveryLabel')}
            mono
            autoComplete="off"
            autoCapitalize="characters"
            spellCheck={false}
            placeholder="XXXXX-XXXXX"
            autoFocus
            value={code}
            onChange={(e) => setCode(e.target.value)}
            error={fieldError}
          />
        )}
        {method === 'securityKey' && busy && (
          <p className={styles.server} role="status">
            {t('twoStep.waiting')}
          </p>
        )}
        <Button type="submit" size="lg" block busy={busy}>
          {method === 'securityKey' ? t('twoStep.tryKeyAgain') : t('twoStep.verify')}
        </Button>
        <div className={styles.alternatives}>
          {methods
            .filter((m) => m !== method)
            .map((m) => (
              <button key={m} type="button" className={styles.link} onClick={() => choose(m)} disabled={busy}>
                {t(SWITCH_TO[m])}
              </button>
            ))}
        </div>
      </form>
    </AuthLayout>
  );
}
