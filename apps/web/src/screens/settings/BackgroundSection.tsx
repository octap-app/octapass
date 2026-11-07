import { Switch, useToast } from '@octapass/ui';
import type { BackgroundStatus } from '@octapass/vault-client';
import { useEffect, useState } from 'react';
import { useService } from '../../app/ServiceContext';
import { Alert } from '../../components/Alert';
import { t } from '../../i18n';
import { errorMessage } from '../../lib/errors';
import { Section } from './SettingsPage';
import styles from './SettingsPage.module.css';

/** Settings → Running in the background, in the desktop app: the tray icon and opening at login. */
export function BackgroundSection() {
  const background = useService().background;
  const toast = useToast();
  const [status, setStatus] = useState<BackgroundStatus>();
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let live = true;
    background?.status().then(
      (next) => live && setStatus(next),
      () => undefined,
    );
    return () => {
      live = false;
    };
  }, [background]);

  if (!background || !status) return null;

  async function run(action: () => Promise<BackgroundStatus>) {
    setBusy(true);
    try {
      setStatus(await action());
    } catch (e) {
      toast({ message: errorMessage(e), tone: 'danger' });
    } finally {
      setBusy(false);
    }
  }

  const mac = status.platform === 'macos';
  return (
    <Section id="background" title={t('background.title')} description={t('background.help')}>
      <div className={styles.row}>
        <Switch
          label={mac ? t('background.menuBar') : t('background.tray')}
          description={t('background.trayHelp')}
          checked={status.tray}
          disabled={busy}
          onChange={(visible) => void run(() => background.setTray(visible))}
        />
      </div>
      <div className={styles.row}>
        <Switch
          label={t('background.openAtLogin')}
          description={status.installed ? t('background.openAtLoginHelp') : t('background.notInstalled')}
          checked={status.openAtLogin}
          // From a disk image it can still be turned off, not on.
          disabled={busy || (!status.installed && !status.openAtLogin)}
          onChange={(enabled) => void run(() => background.setOpenAtLogin(enabled))}
        />
      </div>
      {status.error && <Alert tone="warn">{t('background.failed', { error: status.error })}</Alert>}
    </Section>
  );
}
