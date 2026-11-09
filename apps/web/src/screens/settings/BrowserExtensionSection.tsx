import { Button, useToast } from '@octapass/ui';
import type { BrowserExtensionStatus } from '@octapass/vault-client';
import { useState } from 'react';
import { useService } from '../../app/ServiceContext';
import { t } from '../../i18n';
import { listBrowsers, useBrowserExtension } from '../../lib/browserExtension';
import { errorMessage } from '../../lib/errors';
import { Row, Section } from './SettingsPage';
import styles from './SettingsPage.module.css';

/** The browsers the links are for when none was found: one of each store's. */
const EVERY_STORE = ['Chrome', 'Edge', 'Firefox'];

/**
 * Settings → Browser extension, in the desktop app: Connect (the Browser menu's, too) writes the
 * native messaging manifest for each browser on this computer, and the links get the extension.
 * They're always here, also after the vault window's offer was closed.
 */
export function BrowserExtensionSection() {
  const extension = useService().browserExtension;
  const toast = useToast();
  const { status, run } = useBrowserExtension(extension);
  const [busy, setBusy] = useState(false);

  if (!extension || !status) return null;

  async function change(action: () => Promise<BrowserExtensionStatus>, connecting: boolean) {
    setBusy(true);
    try {
      const next = await run(action);
      if (connecting && next.connected.length === 0) toast({ message: t('browserExtension.none') });
    } catch (e) {
      toast({ message: t('browserExtension.failed', { error: errorMessage(e) }), tone: 'danger' });
    } finally {
      setBusy(false);
    }
  }

  const get = (browser: string) => {
    extension.get(browser).catch((e: unknown) => toast({ message: errorMessage(e), tone: 'danger' }));
  };

  const browsers = status.browsers.length > 0 ? status.browsers.map((browser) => browser.name) : EVERY_STORE;
  const connected = status.connected.length > 0;
  return (
    <Section id="browser-extension" title={t('browserExtension.title')} description={t('browserExtension.help')}>
      <Row
        label={connected ? t('browserExtension.connected', { browsers: listBrowsers(status.connected) }) : t('browserExtension.notConnected')}
        description={status.seen.length > 0 ? t('browserExtension.seen', { browsers: listBrowsers(status.seen) }) : t('browserExtension.notSeen')}
      >
        <Button variant="secondary" size="sm" disabled={busy} onClick={() => void change(() => extension.connect(), true)}>
          {t('browserExtension.connect')}
        </Button>
        {connected && (
          <Button variant="ghost" size="sm" disabled={busy} onClick={() => void change(() => extension.disconnect(), false)}>
            {t('browserExtension.disconnect')}
          </Button>
        )}
      </Row>
      <Row label={t('browserExtension.offerTitle')} description={t('browserExtension.getHelp')}>
        <div className={styles.links}>
          {browsers.map((name) => (
            <Button key={name} variant="secondary" size="sm" icon="external" onClick={() => get(name)}>
              {t('browserExtension.getFor', { browser: name })}
            </Button>
          ))}
        </div>
      </Row>
    </Section>
  );
}
