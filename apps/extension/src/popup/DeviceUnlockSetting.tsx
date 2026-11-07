import type { DevicePlatform } from '@octapass/vault-client';
import { useService } from '@octapass/web/src/app/ServiceContext';
import { t } from '@octapass/web/src/i18n';
import { deviceMethodName } from '@octapass/web/src/lib/deviceUnlock';
import { DeviceUnlockRow } from '@octapass/web/src/screens/settings/DeviceUnlockRow';
import { Row } from '@octapass/web/src/screens/settings/SettingsPage';
import { useEffect, useState } from 'react';
import { tx } from '../i18n';

const DESKTOP_APP = 'https://octap.app/docs/platforms/desktop/';

/**
 * Settings → Security → Unlock with this device. Firefox lets an extension use WebAuthn only for a
 * website's domain it has host permissions for, never for the extension itself, so the passkey the
 * web vault makes (`rp.id = location.hostname`) fails here with "SecurityError: The operation is
 * insecure". In Firefox this row points to the desktop app instead (plan 13 History, 2026-11-04).
 */
export function DeviceUnlockSetting() {
  return chrome.runtime.getURL('').startsWith('moz-extension:') ? <ThroughDesktopApp /> : <DeviceUnlockRow />;
}

function ThroughDesktopApp() {
  const service = useService();
  const [platform, setPlatform] = useState<DevicePlatform>();

  useEffect(() => {
    let live = true;
    void service.getUnlockMethods().then((methods) => live && setPlatform(methods.platform));
    return () => {
      live = false;
    };
  }, [service]);

  if (!platform) return null;
  const method = deviceMethodName(platform);
  return (
    <Row
      label={t('unlock.settingTitle', { method })}
      description={
        <>
          {tx('desktop.firefoxDeviceUnlock', { method })}{' '}
          <a href={DESKTOP_APP} target="_blank" rel="noopener noreferrer">
            {tx('desktop.getApp')}
          </a>
        </>
      }
    />
  );
}
