import { Switch } from '@octapass/ui';
import { Section } from '@octapass/web/src/screens/settings/SettingsPage';
import webStyles from '@octapass/web/src/screens/settings/SettingsPage.module.css';
import { useEffect, useState } from 'react';
import { FILL_ON_LOAD_KEY, fillOnLoadEnabled } from '../background/fillOnLoad';
import { tx } from '../i18n';

/** "Fill logins when a page opens": off unless turned on, per device, in `chrome.storage.local`. */
export function FillOnLoad() {
  const [enabled, setEnabled] = useState(false);

  useEffect(() => void fillOnLoadEnabled().then(setEnabled), []);

  function change(next: boolean) {
    setEnabled(next);
    void chrome.storage.local.set({ [FILL_ON_LOAD_KEY]: next });
  }

  return (
    <Section id="fill-on-load" title={tx('fillOnLoad.title')}>
      <div className={webStyles.row}>
        <Switch label={tx('fillOnLoad.label')} description={tx('fillOnLoad.help')} checked={enabled} onChange={change} />
      </div>
    </Section>
  );
}
