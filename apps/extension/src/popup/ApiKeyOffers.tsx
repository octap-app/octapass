import { Switch } from '@octapass/ui';
import { Section } from '@octapass/web/src/screens/settings/SettingsPage';
import webStyles from '@octapass/web/src/screens/settings/SettingsPage.module.css';
import { useEffect, useState } from 'react';
import { API_KEY_OFFERS_KEY, apiKeyOffersEnabled } from '../background/apiKeys';
import { tx } from '../i18n';

/** "Offer to save API keys": per device, in `chrome.storage.local`, where the service worker reads it. */
export function ApiKeyOffers() {
  const [enabled, setEnabled] = useState(true);

  useEffect(() => void apiKeyOffersEnabled().then(setEnabled), []);

  function change(next: boolean) {
    setEnabled(next);
    void chrome.storage.local.set({ [API_KEY_OFFERS_KEY]: next });
  }

  return (
    <Section id="api-keys" title={tx('apiKeys.title')}>
      <div className={webStyles.row}>
        <Switch label={tx('apiKeys.offer')} description={tx('apiKeys.offerHelp')} checked={enabled} onChange={change} />
      </div>
    </Section>
  );
}
