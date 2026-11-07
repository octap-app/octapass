import { Button, Switch } from '@octapass/ui';
import { Row, Section } from '@octapass/web/src/screens/settings/SettingsPage';
import styles from '@octapass/web/src/screens/settings/SettingsPage.module.css';
import { useEffect, useState } from 'react';
import { td } from './i18n';
import type { PasskeyProvider, ProviderStatus } from './passkeyProvider';

/**
 * Settings → Passkeys in Windows. The switch registers Octa Pass with Windows or removes it; Windows
 * then asks the user to turn it on in its own Settings, and only the state it reports is shown.
 */
export function PasskeyProviderSection({ provider }: { provider: PasskeyProvider }) {
  const [status, setStatus] = useState<ProviderStatus>();
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let current = true;
    const read = () => void provider.status().then((next) => current && setStatus(next));
    read();
    // The last step happens in Windows Settings, so look again on coming back.
    window.addEventListener('focus', read);
    return () => {
      current = false;
      window.removeEventListener('focus', read);
    };
  }, [provider]);

  if (!status?.available) return null;

  const change = async (enabled: boolean) => {
    setBusy(true);
    setFailed(false);
    try {
      setStatus(await provider.set(enabled));
    } catch {
      setFailed(true);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Section id="passkey-provider" title={td('passkeyProvider.title')} description={td('passkeyProvider.help')}>
      <div className={styles.row}>
        <Switch label={td('passkeyProvider.switch')} description={td('passkeyProvider.switchHelp')} checked={status.registered} disabled={busy} onChange={(enabled) => void change(enabled)} />
      </div>
      {status.registered && !status.enabled && (
        <Row label={td('passkeyProvider.enable')} description={td('passkeyProvider.enableHelp')}>
          <Button variant="secondary" size="sm" onClick={() => void provider.openSettings()}>
            {td('passkeyProvider.openSettings')}
          </Button>
        </Row>
      )}
      {status.registered && status.enabled && <Row label={td('passkeyProvider.enabled')} />}
      {failed && (
        <div className={styles.row} role="alert">
          {td('passkeyProvider.failed')}
        </div>
      )}
    </Section>
  );
}
