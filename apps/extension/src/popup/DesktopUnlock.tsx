import { Button } from '@octapass/ui';
import { isVaultError } from '@octapass/vault-client';
import { useSession } from '@octapass/web/src/app/ServiceContext';
import { Alert } from '@octapass/web/src/components/Alert';
import { errorMessage } from '@octapass/web/src/lib/errors';
import { useEffect, useState } from 'react';
import { isBrowserNotTrusted, type DesktopStatus } from '../background/desktop';
import { tx } from '../i18n';
import { useExtension } from './ExtensionContext';
import styles from './DesktopUnlock.module.css';

const SUPPORTED_BROWSERS = 'https://octap.app/docs/platforms/desktop/#supported-browsers';

function NotTrusted() {
  return (
    <Alert tone="info">
      {tx('desktop.browserNotTrusted')}{' '}
      <a href={SUPPORTED_BROWSERS} target="_blank" rel="noopener noreferrer">
        {tx('desktop.supportedBrowsers')}
      </a>
    </Alert>
  );
}

/**
 * "Unlock with Touch ID in the desktop app", above the lock screen, when the Octa Pass desktop app
 * runs signed in to the same account. The app's prompt may close the popup; the unlock still
 * finishes in the service worker. When the app refused this browser, a note says so instead.
 */
export function DesktopUnlock() {
  const { api } = useExtension();
  const session = useSession();
  const [app, setApp] = useState<DesktopStatus>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();

  useEffect(() => {
    void api.desktopStatus().then(setApp);
  }, [api]);

  if (app?.browserNotTrusted) {
    return (
      <div className={styles.desktop}>
        <NotTrusted />
      </div>
    );
  }
  if (!app?.appRunning || app.status === 'signedOut' || (app.email && app.email !== session.email)) return null;

  async function unlock() {
    setBusy(true);
    setError(undefined);
    try {
      await api.unlockWithDesktop();
    } catch (e) {
      setBusy(false);
      // The app was fine a moment ago but refuses this browser now (it was updated, or the browser was).
      if (isBrowserNotTrusted(e)) setApp({ appRunning: false, browserNotTrusted: true });
      else setError(isVaultError(e, 'deviceUnlockFailed') ? tx('desktop.otherAccount') : errorMessage(e));
    }
  }

  return (
    <div className={styles.desktop}>
      {error && <Alert>{error}</Alert>}
      <Button size="lg" block variant="secondary" icon="fingerprint" className={styles.unlock} busy={busy} onClick={() => void unlock()}>
        {app.label ? tx('desktop.unlockWith', { method: app.label }) : tx('desktop.unlock')}
      </Button>
      {busy && <p className={styles.status} role="status">{tx('desktop.waiting')}</p>}
    </div>
  );
}
