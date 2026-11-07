import { Button, Icon, Spinner } from '@octapass/ui';
import { isLocalServer, isVaultError, type UnlockMethods } from '@octapass/vault-client';
import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router';
import { useService, useSession } from '../../app/ServiceContext';
import { useSettings } from '../../app/settings';
import { Alert } from '../../components/Alert';
import { PasswordInput } from '../../components/PasswordInput';
import { t } from '../../i18n';
import { deviceIcon, deviceMethodName } from '../../lib/deviceUnlock';
import { errorMessage } from '../../lib/errors';
import { LocalVaultList } from '../local/LocalChoices';
import { useLocalVaults } from '../local/useLocalVaults';
import { AuthLayout } from './AuthLayout';
import styles from './Lock.module.css';

type Mode = 'loading' | 'device' | 'password';

export function Lock() {
  const service = useService();
  const session = useSession();
  const { settings } = useSettings();
  const [methods, setMethods] = useState<UnlockMethods>();
  const [mode, setMode] = useState<Mode>('loading');
  const [prompting, setPrompting] = useState(false);
  const [deviceError, setDeviceError] = useState<string>();
  const autoStarted = useRef(false);

  const unlockWithDevice = useCallback(async () => {
    setPrompting(true);
    setDeviceError(undefined);
    try {
      await service.unlockWithDevice();
    } catch (e) {
      setPrompting(false);
      if (isVaultError(e, 'passwordRequired')) {
        setMethods((m) => m && { ...m, passwordRequired: true });
        setMode('password');
      } else if (isVaultError(e, 'deviceUnlockFailed')) {
        setMethods((m) => m && { ...m, deviceUnlockEnabled: false });
        setDeviceError(errorMessage(e));
        setMode('password');
      } else if (isVaultError(e, 'deviceUnlockUnsupported')) {
        // No passkey path here (PRF unsupported, or a page whose origin can't use WebAuthn): fall back.
        setMethods((m) => m && { ...m, deviceUnlockEnabled: false });
        setDeviceError(errorMessage(e));
        setMode('password');
      } else {
        setDeviceError(errorMessage(e));
      }
    }
  }, [service]);

  useEffect(() => {
    let live = true;
    // Plan 18: staying unlocked, the vault opens without a prompt when it can; only if it can't
    // does the lock screen ask as before.
    const opened = service.unlockStayUnlocked ? service.unlockStayUnlocked().catch(() => false) : Promise.resolve(false);
    opened.then((done) => (done ? undefined : service.getUnlockMethods())).then(
      (next) => {
        if (!live || !next) return;
        setMethods(next);
        // "Open with device auth" is its own per-device gate; off means the master password at open.
        const useDevice = next.deviceUnlockEnabled && !next.passwordRequired && settings.requireDeviceAuthOnAppOpen;
        setMode(useDevice ? 'device' : 'password');
        // Start the device prompt straight away, once: the master password stays one click away.
        if (useDevice && !autoStarted.current) {
          autoStarted.current = true;
          void unlockWithDevice();
        }
      },
      () => live && setMode('password'),
    );
    return () => {
      live = false;
    };
  }, [service, unlockWithDevice, settings.requireDeviceAuthOnAppOpen]);

  const local = isLocalServer(session.serverUrl);
  const others = useLocalVaults().vaults.filter((vault) => !vault.current);
  const method = methods ? deviceMethodName(methods.platform) : '';
  const canUseDevice = Boolean(methods?.deviceUnlockEnabled && !methods.passwordRequired);

  return (
    <AuthLayout
      title={t('lock.title')}
      subtitle={session.email}
      footer={
        local ? (
          <button type="button" className={styles.link} onClick={() => void service.local?.leave()}>
            {t('localVault.addVault')}
          </button>
        ) : (
          <button type="button" className={styles.link} onClick={() => void service.signOut()}>
            {t('lock.signOut')}
          </button>
        )
      }
    >
      {mode === 'loading' ? (
        <div className={styles.loading}>
          <Spinner size={22} />
        </div>
      ) : mode === 'device' && methods ? (
        <div className={styles.device}>
          <button type="button" className={styles.deviceButton} onClick={() => void unlockWithDevice()} disabled={prompting} aria-describedby="device-status">
            <span className={styles.deviceIcon} data-prompting={prompting || undefined}>
              <Icon name={deviceIcon(methods.platform)} size={40} strokeWidth={1.5} />
            </span>
            <span className={styles.deviceLabel}>{t('lock.unlockWith', { method })}</span>
          </button>
          <p id="device-status" className={styles.status} role="status">
            {prompting ? t('lock.waiting', { method }) : deviceError}
          </p>
          <Button variant="secondary" size="lg" block onClick={() => setMode('password')}>
            {t('lock.usePassword')}
          </Button>
        </div>
      ) : (
        <PasswordForm
          notice={methods?.passwordRequired ? t('lock.passwordRequired') : deviceError}
          onUseDevice={canUseDevice ? () => setMode('device') : undefined}
          method={method}
        />
      )}
      {others.length > 0 && <LocalVaultList vaults={others} heading={t('localVault.switchVault')} />}
    </AuthLayout>
  );
}

function PasswordForm({ notice, onUseDevice, method }: { notice?: string; onUseDevice?: () => void; method: string }) {
  const service = useService();
  const navigate = useNavigate();
  const session = useSession();
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!password) {
      setError(t('validation.passwordRequired'));
      return;
    }
    setBusy(true);
    setError(undefined);
    try {
      await service.unlock(password);
    } catch (e) {
      setError(errorMessage(e));
      setPassword('');
      setBusy(false);
    }
  }

  return (
    <form className={styles.form} onSubmit={submit} noValidate>
      {notice && <Alert tone="info">{notice}</Alert>}
      {/* A hidden username lets password managers and the browser pair the password with the account. */}
      <input type="email" name="username" autoComplete="username" value={session.email ?? ''} readOnly hidden />
      <PasswordInput label={t('fields.masterPassword')} autoComplete="current-password" autoFocus value={password} onChange={(e) => setPassword(e.target.value)} error={error} />
      <Button type="submit" size="lg" block busy={busy} icon="lock">
        {t('lock.unlock')}
      </Button>
      {onUseDevice && (
        <Button variant="ghost" onClick={onUseDevice}>
          {t('lock.unlockWith', { method })}
        </Button>
      )}
      {service.startPasswordReset && !isLocalServer(session.serverUrl) && (
        <Button variant="ghost" onClick={() => navigate('/reset')}>
          {t('signIn.forgotPassword')}
        </Button>
      )}
    </form>
  );
}
