import { Button, Switch, useToast } from '@octapass/ui';
import { isVaultError, type UnlockMethods } from '@octapass/vault-client';
import { useEffect, useState } from 'react';
import { useService } from '../../app/ServiceContext';
import { Alert } from '../../components/Alert';
import { t } from '../../i18n';
import { deviceMethodHelp, deviceMethodName } from '../../lib/deviceUnlock';
import { errorMessage } from '../../lib/errors';
import styles from './SettingsPage.module.css';

/** Settings → Security → Unlock with this device (Touch ID, Windows Hello, device passcode). */
export function DeviceUnlockRow() {
  const service = useService();
  const toast = useToast();
  const [methods, setMethods] = useState<UnlockMethods>();
  const [busy, setBusy] = useState(false);
  const [unsupported, setUnsupported] = useState(false);
  // The passkey is made but the browser wants another click to read its key.
  const [confirming, setConfirming] = useState(false);

  useEffect(() => {
    let live = true;
    void service.getUnlockMethods().then((next) => {
      if (!live) return;
      setMethods(next);
      setUnsupported(!next.deviceUnlockSupported);
    });
    return () => {
      live = false;
    };
  }, [service]);

  if (!methods) return null;
  const method = deviceMethodName(methods.platform);

  async function toggle(on: boolean) {
    setBusy(true);
    try {
      if (on) await service.enableDeviceUnlock();
      else await service.disableDeviceUnlock();
      setConfirming(false);
      setMethods(await service.getUnlockMethods());
      toast({ message: on ? t('unlock.enabled', { method }) : t('unlock.disabled', { method }), tone: 'success' });
    } catch (e) {
      setConfirming(isVaultError(e, 'deviceUnlockConfirm'));
      if (isVaultError(e, 'deviceUnlockUnsupported')) setUnsupported(true);
      else if (!isVaultError(e, 'deviceUnlockConfirm')) toast({ message: errorMessage(e), tone: isVaultError(e, 'deviceUnlockCancelled') ? 'neutral' : 'danger', icon: 'info' });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className={styles.row}>
      <div className={styles.stack}>
        <Switch
          label={t('unlock.settingTitle', { method })}
          description={methods.deviceUnlockEnabled ? t('unlock.onHelp') : deviceMethodHelp(methods.platform)}
          checked={methods.deviceUnlockEnabled}
          disabled={busy || (unsupported && !methods.deviceUnlockEnabled)}
          onChange={(on) => void toggle(on)}
        />
        {unsupported && !methods.deviceUnlockEnabled && <Alert tone="info">{t('unlock.unsupported')}</Alert>}
        {confirming && !methods.deviceUnlockEnabled && (
          <Alert
            tone="info"
            action={
              <Button variant="secondary" size="sm" busy={busy} onClick={() => void toggle(true)}>
                {t('unlock.confirm', { method })}
              </Button>
            }
          >
            {t('unlock.confirmHelp')}
          </Alert>
        )}
      </div>
    </div>
  );
}
