import { Switch } from '@octapass/ui';
import { t } from '../../i18n';
import { useLocationSetting, useSuggestSetting } from '../../lib/here';
import { Section } from './SettingsPage';
import styles from './SettingsPage.module.css';

/** Settings → Nearby: whether this device reads its location for Nearby, and the place suggestion. Both device-only. */
export function NearbySection() {
  const [location, setLocation] = useLocationSetting();
  const [suggest, setSuggest] = useSuggestSetting();
  return (
    <Section id="nearby" title={t('nearby.settingsTitle')}>
      <div className={styles.row}>
        <Switch label={t('nearby.locationSetting')} description={t('nearby.locationSettingHint')} checked={location} onChange={setLocation} />
      </div>
      <div className={styles.row}>
        <Switch label={t('nearby.suggestSetting')} description={t('nearby.suggestSettingHint')} checked={suggest} onChange={setSuggest} />
      </div>
    </Section>
  );
}
