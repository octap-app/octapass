import { Button, IconButton, Ring, Segmented, Switch, useToast } from '@octapass/ui';
import { isLocalServer, type ServerInfo, type StorageUsage } from '@octapass/vault-client';
import { useEffect, useId, useState, type ReactNode } from 'react';
import { useLocation, useNavigate } from 'react-router';
import { useService, useSession } from '../../app/ServiceContext';
import { AUTO_LOCK_CHOICES, LANGUAGE_NAMES, useSettings, type ThemePreference } from '../../app/settings';
import { formatBytes, LOCALES, t, type LanguagePreference } from '../../i18n';
import { useCopy } from '../../lib/clipboard';
import { useConfirmIdentity } from '../../lib/identityGate';
import { errorMessage } from '../../lib/errors';
import { LocalSection } from '../local/LocalSection';
import { PageHeader } from '../PageHeader';
import { useClientPolicies } from '../../lib/useOrganisation';
import { useSharing } from '../../lib/useSharing';
import { useStayUnlocked } from '../../lib/stayUnlocked';
import { ChangePassword } from './ChangePassword';
import { RotateSecretKey } from './RotateSecretKey';
import { VaultKeysRow } from './VaultKeysRow';
import { DeleteAccount } from './DeleteAccount';
import { DeviceAuthSection } from './DeviceAuthSection';
import { DevicesSection } from './DevicesSection';
import { EquivalentDomainsSection } from './EquivalentDomainsSection';
import { DeviceUnlockRow } from './DeviceUnlockRow';
import { BackgroundSection } from './BackgroundSection';
import { ExportDialog } from './ExportDialog';
import { ImportPanel } from './ImportPanel';
import { SshAgentSection } from './SshAgentSection';
import { TwoStepSection } from './TwoStepSection';
import { ConnectSection } from './ConnectSection';
import { WifiSection } from './WifiSection';
import styles from './SettingsPage.module.css';

export function Section({ id, title, description, children }: { id?: string; title: string; description?: ReactNode; children: ReactNode }) {
  const titleId = `${useId()}-title`;
  return (
    <section id={id} className={styles.section} aria-labelledby={titleId}>
      <div className={styles.sectionHead}>
        <h2 id={titleId}>{title}</h2>
        {description && <p>{description}</p>}
      </div>
      <div className={styles.card}>{children}</div>
    </section>
  );
}

export function Row({ label, description, children }: { label: ReactNode; description?: ReactNode; children?: ReactNode }) {
  return (
    <div className={styles.row}>
      <div className={styles.rowText}>
        <span className={styles.rowLabel}>{label}</span>
        {description && <span className={styles.rowDescription}>{description}</span>}
      </div>
      {children && <div className={styles.rowControl}>{children}</div>}
    </div>
  );
}

/** System, then each language named in itself, so anyone can find their own. */
export function LanguageRow() {
  const { settings, update } = useSettings();
  return (
    <Row label={t('settings.language')} description={t('settings.languageHelp')}>
      <Segmented<LanguagePreference>
        label={t('settings.language')}
        value={settings.language}
        onChange={(language) => update({ language })}
        options={[{ value: 'system', label: t('settings.languageSystem') }, ...LOCALES.map((locale) => ({ value: locale, label: LANGUAGE_NAMES[locale], lang: locale }))]}
      />
    </Row>
  );
}

/** "Show website icons", on by default. The note says where icons come from. */
export function SiteIconsRow({ local }: { local?: boolean }) {
  const { settings, update } = useSettings();
  const session = useSession();
  const withoutAccount = local ?? !/^https?:\/\//i.test(session.serverUrl ?? '');
  return (
    <div className={styles.row}>
      <Switch
        label={t('settings.siteIcons')}
        description={withoutAccount ? t('settings.siteIconsHelpLocal') : t('settings.siteIconsHelp')}
        checked={settings.showSiteIcons}
        onChange={(showSiteIcons) => update({ showSiteIcons })}
      />
    </div>
  );
}

/** `platformSection`: the app's own settings after Security (the phone's AutoFill). */
export function SettingsPage({ platformSection }: { platformSection?: ReactNode } = {}) {
  const { settings, update } = useSettings();
  const service = useService();
  const session = useSession();
  const location = useLocation();
  const navigate = useNavigate();
  const sharing = useSharing();
  const { maxAutoLockMinutes } = useClientPolicies();
  // Plan 18: no lock timer and no lock when hidden while staying unlocked.
  const staying = useStayUnlocked().active && !maxAutoLockMinutes;
  const local = Boolean(service.local) && isLocalServer(session.serverUrl);
  const [exportOpen, setExportOpen] = useState(false);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [passwordOpen, setPasswordOpen] = useState(false);
  const [rotateOpen, setRotateOpen] = useState(false);

  useEffect(() => {
    if (location.hash) document.getElementById(decodeURIComponent(location.hash.slice(1)))?.scrollIntoView({ block: 'start' });
  }, [location.hash]);

  return (
    <div className={styles.page}>
      <PageHeader title={t('settings.title')} />
      <div className={styles.body}>
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
          <SiteIconsRow />
        </Section>

        <Section id="security" title={t('settings.security')}>
          <Row label={<label htmlFor="auto-lock">{t('settings.autoLock')}</label>} description={maxAutoLockMinutes ? t('organisation.policyAutoLock', { minutes: maxAutoLockMinutes }) : t('settings.autoLockHelp')}>
            <select id="auto-lock" className={styles.select} value={settings.autoLockMinutes} disabled={staying} onChange={(e) => update({ autoLockMinutes: Number(e.target.value) })}>
              {AUTO_LOCK_CHOICES.filter((minutes) => !maxAutoLockMinutes || (minutes > 0 && minutes <= maxAutoLockMinutes)).map((minutes) => (
                <option key={minutes} value={minutes}>
                  {minutes === 0 ? t('settings.autoLockNever') : minutes >= 60 ? t('settings.hours', { count: minutes / 60 }) : t('settings.minutes', { count: minutes })}
                </option>
              ))}
            </select>
          </Row>
          <div className={styles.row}>
            <Switch label={t('settings.lockOnHide')} description={t('settings.lockOnHideHelp')} checked={settings.lockOnHide} disabled={staying} onChange={(lockOnHide) => update({ lockOnHide })} />
          </div>
          <DeviceUnlockRow />
          <Row label={t('settings.lockNow')} description={t('settings.lockNowHelp')}>
            <Button variant="secondary" size="sm" icon="lock" onClick={() => service.lock()}>
              {t('settings.lockNow')}
            </Button>
          </Row>
          {service.changeMasterPassword && (
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

        {local && <LocalSection />}

        {platformSection}

        <DeviceAuthSection webVault={!service.setFillGate} autofill={Boolean(service.setFillGate)} local={local} />
        <EquivalentDomainsSection />

        <BackgroundSection />
        <WifiSection />
        <ConnectSection />

        <SshAgentSection />

        {!local && <TwoStepSection />}

        <DevicesSection />

        <Section id="export" title={t('settings.export')} description={t('settings.exportHelp')}>
          <Row label={t('settings.exportVault')} description={t('export.rowHelp')}>
            <Button variant="secondary" size="sm" icon="download" onClick={() => setExportOpen(true)}>
              {t('settings.exportAction')}
            </Button>
          </Row>
        </Section>

        <Section id="import" title={t('settings.import')} description={t('settings.importHelp')}>
          <ImportPanel />
        </Section>

        {!local && <Section id="account" title={t('settings.account')}>
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
        </Section>}

        <p className={styles.about}>{t('settings.about')}</p>
      </div>

      <ExportDialog open={exportOpen} onClose={() => setExportOpen(false)} />
      <DeleteAccount open={deleteOpen} onClose={() => setDeleteOpen(false)} />
      {service.changeMasterPassword && <ChangePassword open={passwordOpen} onClose={() => setPasswordOpen(false)} />}
      {service.rotateSecretKey && <RotateSecretKey open={rotateOpen} onClose={() => setRotateOpen(false)} />}
    </div>
  );
}

export function SecretKeyRow() {
  const service = useService();
  const copy = useCopy();
  const confirm = useConfirmIdentity();
  const toast = useToast();
  const [secretKey, setSecretKey] = useState<string>();

  async function reveal() {
    try {
      if (!(await confirm({ reason: t('identityGate.body') }))) return;
      setSecretKey(await service.getSecretKey());
    } catch (e) {
      toast({ message: errorMessage(e), tone: 'danger' });
    }
  }

  async function copyKey(value: string) {
    if (!(await confirm({ reason: t('identityGate.body') }))) return;
    await copy(value, t('fields.secretKey'));
  }

  return (
    <Row label={t('fields.secretKey')} description={secretKey ? <span className={`mono ${styles.secret}`}>{secretKey}</span> : t('settings.secretKeyHelp')}>
      {secretKey ? (
        <>
          <IconButton icon="copy" size="sm" label={t('copy.action', { what: t('fields.secretKey') })} onClick={() => void copyKey(secretKey)} />
          <IconButton icon="eyeOff" size="sm" label={t('common.hideWhat', { what: t('fields.secretKey') })} onClick={() => setSecretKey(undefined)} />
        </>
      ) : (
        <Button variant="secondary" size="sm" icon="eye" onClick={() => void reveal()}>
          {t('common.show')}
        </Button>
      )}
    </Row>
  );
}

export function StorageRow() {
  const service = useService();
  const [usage, setUsage] = useState<StorageUsage | 'failed'>();

  useEffect(() => {
    let live = true;
    service.attachments!.getStorageUsage().then(
      (next) => live && setUsage(next),
      () => live && setUsage('failed'),
    );
    return () => {
      live = false;
    };
  }, [service]);

  if (usage === 'failed') return <Row label={t('settings.storage')} description={t('settings.storageFailed')} />;
  const share = usage ? usage.attachmentBytes / usage.maxAttachmentBytes : 0;
  const description = usage && (
    <>
      {t('settings.storageUsed', { used: formatBytes(usage.attachmentBytes), total: formatBytes(usage.maxAttachmentBytes) })}. {t('settings.storageFileLimit', { size: formatBytes(usage.maxFileBytes) })}{' '}
      {t('settings.storageHelp')}
    </>
  );
  return (
    <Row label={t('settings.storage')} description={description}>
      {usage && <Ring value={share} size={32} tone={share > 0.9 ? 'danger' : share > 0.75 ? 'warn' : 'trust'} />}
    </Row>
  );
}

export function ServerRow({ serverUrl }: { serverUrl?: string }) {
  const service = useService();
  const [info, setInfo] = useState<ServerInfo | 'unreachable'>();

  useEffect(() => {
    if (!serverUrl) return;
    let live = true;
    service.getServerInfo(serverUrl).then(
      (next) => live && setInfo(next),
      () => live && setInfo('unreachable'),
    );
    return () => {
      live = false;
    };
  }, [service, serverUrl]);

  const description =
    info === 'unreachable' ? t('settings.serverUnreachable', { url: serverUrl ?? '' }) : info ? t('settings.serverInfo', { name: info.name, url: serverUrl ?? '', version: info.version }) : serverUrl;
  return <Row label={t('settings.server')} description={description} />;
}
