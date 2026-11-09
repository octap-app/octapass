import { Icon, IconButton, useToast } from '@octapass/ui';
import type { BrowserExtensionService } from '@octapass/vault-client';
import { useState } from 'react';
import { t } from '../../i18n';
import { dismissOffer, extensionOffer, listBrowsers, offerDismissed, useBrowserExtension } from '../../lib/browserExtension';
import { errorMessage } from '../../lib/errors';
import styles from './ExtensionOffer.module.css';

/**
 * A quiet card at the foot of the desktop app's sidebar: the Octa Pass extension, for the browsers on
 * this computer, until one has reached the app; or Connect, when it has but can't any more. × hides
 * it on this device; Settings → Browser extension keeps the links.
 */
export function ExtensionOffer({ extension }: { extension: BrowserExtensionService }) {
  const toast = useToast();
  const { status, run } = useBrowserExtension(extension);
  const [dismissed, setDismissed] = useState(offerDismissed);
  const [busy, setBusy] = useState(false);

  const offer = status && extensionOffer(status);
  if (!status || !offer || dismissed) return null;

  const dismiss = () => {
    dismissOffer();
    setDismissed(true);
  };

  async function connect() {
    setBusy(true);
    try {
      const next = await run(() => extension.connect());
      if (next.connected.length === 0) toast({ message: t('browserExtension.none') });
    } catch (e) {
      toast({ message: t('browserExtension.failed', { error: errorMessage(e) }), tone: 'danger' });
    } finally {
      setBusy(false);
    }
  }

  const get = (browser: string) => {
    extension.get(browser).catch((e: unknown) => toast({ message: errorMessage(e), tone: 'danger' }));
  };

  const names = status.browsers.map((browser) => browser.name);
  return (
    <aside className={styles.card} aria-labelledby="extension-offer-title">
      <span className={styles.icon} aria-hidden="true">
        <Icon name="login" size={18} />
      </span>
      <div className={styles.text}>
        <h2 id="extension-offer-title" className={styles.title}>
          {offer === 'get' ? t('browserExtension.offerTitle') : t('browserExtension.offerConnectTitle')}
        </h2>
        <p className={styles.body}>{offer === 'get' ? t('browserExtension.offerBody', { browsers: listBrowsers(names) }) : t('browserExtension.offerConnectBody')}</p>
        {offer === 'get' &&
          names.map((name) => (
            <button key={name} type="button" className={styles.link} onClick={() => get(name)}>
              {t('browserExtension.getFor', { browser: name })}
              <Icon name="external" size={14} />
            </button>
          ))}
        {(offer === 'connect' || status.connected.length === 0) && (
          <button type="button" className={styles.link} disabled={busy} onClick={() => void connect()}>
            {offer === 'connect' ? t('browserExtension.connect') : t('browserExtension.offerConnect')}
          </button>
        )}
      </div>
      <IconButton icon="close" size="sm" label={t('browserExtension.offerDismiss')} className={styles.close} onClick={dismiss} />
    </aside>
  );
}
