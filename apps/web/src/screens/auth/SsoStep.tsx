import { Button, TextField } from '@octapass/ui';
import { isVaultError, type SignInResult, type SsoRequired } from '@octapass/vault-client';
import { useState, type FormEvent } from 'react';
import { useService } from '../../app/ServiceContext';
import { Alert } from '../../components/Alert';
import { t } from '../../i18n';
import { errorMessage } from '../../lib/errors';
import { AuthLayout } from './AuthLayout';
import styles from './SignIn.module.css';

/**
 * The step after the master password when an organisation requires SSO. The identity provider
 * opens in a browser and ends on a page with a code, which ties that browser to this device. SSO
 * only lets the sign-in go on: the master password already unlocked the keys on this device.
 */
export function SsoStep({ sso, onNext, onStartOver }: { sso: SsoRequired; onNext: (result: SignInResult) => void; onStartOver: (error?: string) => void }) {
  const service = useService();
  const [code, setCode] = useState('');
  const [fieldError, setFieldError] = useState<string>();
  const [formError, setFormError] = useState<string>();
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    const typed = code.replace(/\s/g, '');
    if (!/^\d{6}$/.test(typed)) return setFieldError(t('sso.codeRequired'));
    setFieldError(undefined);
    setFormError(undefined);
    setBusy(true);
    try {
      onNext(await service.finishSso!(typed));
    } catch (error) {
      if (isVaultError(error, 'twoStepExpired')) return onStartOver(errorMessage(error));
      setFormError(errorMessage(error));
      setCode('');
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthLayout
      title={t('sso.title')}
      subtitle={t('sso.subtitle', { organisation: sso.orgName })}
      footer={
        <button type="button" className={styles.link} onClick={() => onStartOver()} disabled={busy}>
          {t('twoStep.startOver')}
        </button>
      }
    >
      <form className={styles.form} onSubmit={submit} noValidate>
        {formError && <Alert>{formError}</Alert>}
        <Button type="button" variant="secondary" icon="external" onClick={() => window.open(sso.url, '_blank', 'noopener,noreferrer')}>
          {t('sso.open')}
        </Button>
        <TextField id="sso-url" label={t('sso.address')} hint={t('sso.addressHint')} mono readOnly value={sso.url} onFocus={(e) => e.target.select()} />
        <TextField id="sso-code" label={t('sso.codeLabel')} hint={t('sso.codeHint')} mono inputMode="numeric" autoComplete="off" maxLength={7} value={code} onChange={(e) => setCode(e.target.value)} error={fieldError} />
        <Button type="submit" busy={busy}>
          {t('sso.finish')}
        </Button>
      </form>
    </AuthLayout>
  );
}
