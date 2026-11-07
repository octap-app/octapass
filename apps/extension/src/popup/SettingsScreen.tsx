import { Button, Segmented, Switch } from '@octapass/ui';
import { useService, useSession } from '@octapass/web/src/app/ServiceContext';
import { AUTO_LOCK_CHOICES, useSettings, type ThemePreference } from '@octapass/web/src/app/settings';
import { t } from '@octapass/web/src/i18n';
import { DeleteAccount } from '@octapass/web/src/screens/settings/DeleteAccount';
import { DeviceAuthSection } from '@octapass/web/src/screens/settings/DeviceAuthSection';
import { useStayUnlocked } from '@octapass/web/src/lib/stayUnlocked';
import { useSharing } from '@octapass/web/src/lib/useSharing';
import { EquivalentDomainsSection } from '@octapass/web/src/screens/settings/EquivalentDomainsSection';
import { ExportDialog } from '@octapass/web/src/screens/settings/ExportDialog';
import { ImportPanel } from '@octapass/web/src/screens/settings/ImportPanel';
import { ProvidersSection } from '@octapass/web/src/screens/maskedEmail/MaskedEmailPage';
import { PageHeader } from '@octapass/web/src/screens/PageHeader';
import { ChangePassword } from '@octapass/web/src/screens/settings/ChangePassword';
import { DevicesSection } from '@octapass/web/src/screens/settings/DevicesSection';
import { RotateSecretKey } from '@octapass/web/src/screens/settings/RotateSecretKey';
import { LanguageRow, Row, SecretKeyRow, Section, ServerRow, SiteIconsRow, StorageRow } from '@octapass/web/src/screens/settings/SettingsPage';
import { TwoStepSection } from '@octapass/web/src/screens/settings/TwoStepSection';
import { VaultKeysRow } from '@octapass/web/src/screens/settings/VaultKeysRow';
import webStyles from '@octapass/web/src/screens/settings/SettingsPage.module.css';
import { useEffect, useState } from 'react';
import { useLocation, useNavigate } from 'react-router';
import { DEFAULT_LOCK_SETTINGS, LOCK_SETTINGS_KEY, readLockSettings, type LockSettings } from '../background/autoLock';
import { DEVICE_AUTH_KEY } from '../background/deviceAuth';
import { SITE_ICONS_KEY } from '../background/siteIcons';
import { LANGUAGE_KEY, tx } from '../i18n';
import { LOCAL_SERVER } from '../shared/local';
import { ApiKeyOffers } from './ApiKeyOffers';
import { FillOnLoad } from './FillOnLoad';
import { BrowserAutofillSection } from './BrowserAutofill';
import { browserName } from './browserSettings';
import { DeviceUnlockSetting } from './DeviceUnlockSetting';
import { FrameApprovals } from './FrameApprovals';
import { HttpAuthSites, httpAuthSupported } from './HttpAuthSites';
import { NeverSaveSites } from './NeverSaveSites';
import { LocalSection } from './local/LocalSection';
import styles from './SettingsScreen.module.css';

/** The lock settings live in `chrome.storage.local`, where the service worker reads them. */
function useLockSettings(): [LockSettings, (patch: Partial<LockSettings>) => void] {
  const [settings, setSettings] = useState(DEFAULT_LOCK_SETTINGS);
  useEffect(() => {
    void chrome.storage.local.get(LOCK_SETTINGS_KEY).then((stored) => setSettings(readLockSettings(stored[LOCK_SETTINGS_KEY] as Partial<LockSettings> | undefined)));
  }, []);
  const update = (patch: Partial<LockSettings>) => {
    const next = { ...settings, ...patch };
    setSettings(next);
    void chrome.storage.local.set({ [LOCK_SETTINGS_KEY]: next });
  };
  return [settings, update];
}

export function SettingsScreen() {
  const service = useService();
  const session = useSession();
  const { settings, update } = useSettings();
  const [lock, updateLock] = useLockSettings();
  // Plan 18: no lock timer and no lock with the computer while staying unlocked. The switch itself
  // is in the device-auth section, through the service worker.
  const staying = useStayUnlocked().active;
  const [exportOpen, setExportOpen] = useState(false);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [passwordOpen, setPasswordOpen] = useState(false);
  const [rotateOpen, setRotateOpen] = useState(false);
  const sharing = useSharing();
  const navigate = useNavigate();
  const local = session.serverUrl === LOCAL_SERVER;
  const { hash } = useLocation();

  useEffect(() => {
    if (hash) document.getElementById(decodeURIComponent(hash.slice(1)))?.scrollIntoView({ block: 'start' });
  }, [hash]);

  // Content scripts can't see the app page's localStorage; the service worker answers them from here.
  useEffect(() => void chrome.storage.local.set({ [LANGUAGE_KEY]: settings.language }), [settings.language]);
  useEffect(() => void chrome.storage.local.set({ [SITE_ICONS_KEY]: settings.showSiteIcons }), [settings.showSiteIcons]);
  // The service worker reads the autofill gate from here while filling.
  useEffect(
    () =>
      void chrome.storage.local.set({
        [DEVICE_AUTH_KEY]: {
          requireDeviceAuthOnAppOpen: settings.requireDeviceAuthOnAppOpen,
          requireDeviceAuthOnAutofill: settings.requireDeviceAuthOnAutofill,
          requireDeviceAuthOnRevealCopy: settings.requireDeviceAuthOnRevealCopy,
          requireReauthForCvv: settings.requireReauthForCvv,
        },
      }),
    [settings.requireDeviceAuthOnAppOpen, settings.requireDeviceAuthOnAutofill, settings.requireDeviceAuthOnRevealCopy, settings.requireReauthForCvv],
  );

  return (
    <div className={webStyles.page}>
      <PageHeader title={t('settings.title')} />
      <div className={webStyles.body}>
        <Section title={t('settings.appearance')}>
          <Row label={t('settings.theme')}>
            <Segmented<ThemePreference>
              label={t('settings.theme')}
              value={settings.theme}
              onChange={(theme) => update({ theme })}
              options={[
                { value: 'system', label: t('settings.themeSystem') },
                { value: 'light', label: t('settings.themeLight') },
                { value: 'dark', label: t('settings.themeDark') },
              ]}
            />
          </Row>
          <LanguageRow />
          <SiteIconsRow local={local} />
        </Section>

        <Section title={t('settings.security')}>
          <Row label={<label htmlFor="auto-lock">{t('settings.autoLock')}</label>} description={t('settings.autoLockHelp')}>
            <select id="auto-lock" className={webStyles.select} value={lock.autoLockMinutes} disabled={staying} onChange={(e) => updateLock({ autoLockMinutes: Number(e.target.value) })}>
              {AUTO_LOCK_CHOICES.map((minutes) => (
                <option key={minutes} value={minutes}>
                  {minutes === 0 ? tx('settings.autoLockNever') : minutes >= 60 ? t('settings.hours', { count: minutes / 60 }) : t('settings.minutes', { count: minutes })}
                </option>
              ))}
            </select>
          </Row>
          <div className={webStyles.row}>
            <Switch label={tx('settings.lockOnSystemLock')} description={tx('settings.lockOnSystemLockHelp')} checked={lock.lockOnSystemLock} disabled={staying} onChange={(lockOnSystemLock) => updateLock({ lockOnSystemLock })} />
          </div>
          {!local && <DeviceUnlockSetting />}
          <Row label={t('settings.lockNow')} description={tx('settings.lockNowHelp')}>
            <Button variant="secondary" size="sm" icon="lock" onClick={() => service.lock()}>
              {t('settings.lockNow')}
            </Button>
          </Row>
          {!local && service.changeMasterPassword && (
            <Row label={t('fields.masterPassword')} description={t('changePassword.rowHelp')}>
              <Button variant="secondary" size="sm" icon="key" onClick={() => setPasswordOpen(true)}>
                {t('changePassword.action')}
              </Button>
            </Row>
          )}
          {!local && <SecretKeyRow />}
          {!local && service.rotateSecretKey && (
            <Row label={t('rotateSecretKey.row')} description={t('rotateSecretKey.rowHelp')}>
              <Button variant="secondary" size="sm" icon="refresh" onClick={() => setRotateOpen(true)}>
                {t('rotateSecretKey.action')}
              </Button>
            </Row>
          )}
          {!local && sharing && <VaultKeysRow />}
          {sharing && (
            <Row label={t('settings.securityLog')} description={t('settings.securityLogHelp')}>
              <Button variant="secondary" size="sm" icon="history" onClick={() => navigate('/settings/security-log')}>
                {t('settings.securityLogAction')}
              </Button>
            </Row>
          )}
        </Section>

        {!local && <TwoStepSection />}

        <DevicesSection />

        <DeviceAuthSection autofill local={local} />

        <FillOnLoad />

        <EquivalentDomainsSection />

        <BrowserAutofillSection />

        <FrameApprovals />

        {httpAuthSupported() && <HttpAuthSites />}

        <ApiKeyOffers />

        <NeverSaveSites />

        {/* Masked email needs an account: the token syncs in the vault. */}
        {!local && <ProvidersSection id="masked-email" />}

        <Section id="export" title={t('settings.export')} description={t('settings.exportHelp')}>
          <Row label={t('settings.exportVault')} description={t('settings.exportWarning')}>
            <Button variant="secondary" size="sm" icon="download" onClick={() => setExportOpen(true)}>
              {t('settings.exportAction')}
            </Button>
          </Row>
        </Section>
        <Section id="import" title={t('settings.import')} description={t('settings.importHelp')}>
          <ImportPanel />
        </Section>

        {local ? (
          <LocalSection />
        ) : (
          <Section title={t('settings.account')}>
            <Row label={t('fields.email')} description={<bdi dir="ltr">{session.email}</bdi>} />
            <ServerRow serverUrl={session.serverUrl} />
            {service.attachments && <StorageRow />}
            <Row label={t('settings.signOut')} description={t('settings.signOutHelp')}>
              <Button variant="secondary" size="sm" icon="signOut" onClick={() => void service.signOut()}>
                {t('settings.signOut')}
              </Button>
            </Row>
            <Row label={t('settings.deleteAccount')} description={t('settings.deleteAccountHelp')}>
              <Button variant="danger" size="sm" icon="trash" onClick={() => setDeleteOpen(true)}>
                {t('settings.deleteAccount')}
              </Button>
            </Row>
          </Section>
        )}

        <p className={styles.about}>{tx('settings.about', { browser: browserName() })}</p>
      </div>
      <ExportDialog open={exportOpen} onClose={() => setExportOpen(false)} />
      <DeleteAccount open={deleteOpen} onClose={() => setDeleteOpen(false)} />
      {service.changeMasterPassword && <ChangePassword open={passwordOpen} onClose={() => setPasswordOpen(false)} />}
      {service.rotateSecretKey && <RotateSecretKey open={rotateOpen} onClose={() => setRotateOpen(false)} />}
    </div>
  );
}
