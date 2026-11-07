import { Button, Switch } from '@octapass/ui';
import { useState } from 'react';
import { useService } from '../../app/ServiceContext';
import { useSettings } from '../../app/settings';
import { t } from '../../i18n';
import { loadOffers, saveOffers } from '../../lib/wifi';
import { Row, Section } from './SettingsPage';
import styles from './SettingsPage.module.css';

/** Settings → Wi-Fi, in the apps: the "Save this network?" offers. */
export function WifiSection() {
  const wifi = useService().wifi;
  const { settings, update } = useSettings();
  const [never, setNever] = useState(() => loadOffers().never.length);
  if (!wifi) return null;
  return (
    <Section id="wifi" title={t('wifi.settings')} description={t('wifi.settingsHelp')}>
      <div className={styles.row}>
        <Switch label={t('wifi.offerSetting')} description={t('wifi.offerSettingHelp')} checked={settings.wifiOffers} onChange={(wifiOffers) => update({ wifiOffers })} />
      </div>
      {never > 0 && (
        <Row label={t('wifi.forgetNever', { count: never })}>
          <Button
            variant="secondary"
            size="sm"
            onClick={() => {
              saveOffers({ ...loadOffers(), never: [] });
              setNever(0);
            }}
          >
            {t('wifi.forgetNeverAction')}
          </Button>
        </Row>
      )}
    </Section>
  );
}
