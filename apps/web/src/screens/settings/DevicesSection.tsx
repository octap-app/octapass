import { Button, Icon, TextField, useToast, type IconName } from '@octapass/ui';
import type { Device } from '@octapass/vault-client';
import { useState, type FormEvent } from 'react';
import { ConfirmDialog } from '../../components/ConfirmDialog';
import { formatDate, formatRelative, t, type MessageKey } from '../../i18n';
import { useAction } from '../../lib/useAction';
import { useSharing, useSharingData } from '../../lib/useSharing';
import sharingStyles from '../sharing/Sharing.module.css';
import { Section } from './SettingsPage';

const PHONES = new Set(['ios', 'android']);
const PLATFORMS = new Set(['web', 'extension', 'ios', 'android', 'mac', 'windows', 'linux', 'desktop']);

const platformLabel = (platform: string) => t(`devices.platforms.${PLATFORMS.has(platform) ? platform : 'other'}` as MessageKey);
const platformIcon = (platform: string): IconName => (PHONES.has(platform) ? 'phone' : 'monitor');

/** Settings → Devices: where the account is signed in; rename this one, sign others out. */
export function DevicesSection() {
  const sharing = useSharing();
  const toast = useToast();
  const { data: devices, retry } = useSharingData((s) => s.listDevices());
  const [signingOut, setSigningOut] = useState<Device>();
  if (!sharing) return null;

  return (
    <Section id="devices" title={t('devices.title')} description={t('devices.help')}>
      {!devices ? (
        <p className={sharingStyles.empty}>{t('common.loading')}</p>
      ) : (
        <ul className={sharingStyles.list}>
          {devices.map((device) => (
            <DeviceRow key={device.id} device={device} onRenamed={retry} onSignOut={() => setSigningOut(device)} />
          ))}
        </ul>
      )}
      <ConfirmDialog
        open={signingOut !== undefined}
        title={t('devices.signOutTitle', { name: signingOut?.name ?? '' })}
        confirmLabel={t('devices.signOut')}
        onClose={() => setSigningOut(undefined)}
        onConfirm={async () => {
          await sharing.signOutDevice(signingOut!.id);
          toast({ message: t('devices.signedOut', { name: signingOut!.name }), tone: 'success' });
          retry();
        }}
      >
        {t('devices.signOutBody')}
      </ConfirmDialog>
    </Section>
  );
}

function DeviceRow({ device, onRenamed, onSignOut }: { device: Device; onRenamed: () => void; onSignOut: () => void }) {
  const sharing = useSharing()!;
  const { busy, run } = useAction();
  const [name, setName] = useState<string>();

  async function rename(event: FormEvent) {
    event.preventDefault();
    if (!name?.trim()) return;
    if (await run('rename', () => sharing.renameDevice(name), t('devices.renamed'))) {
      setName(undefined);
      onRenamed();
    }
  }

  return (
    <li className={sharingStyles.person}>
      <div className={sharingStyles.who}>
        <span className={sharingStyles.vaultIcon}>
          <Icon name={platformIcon(device.platform)} size={20} />
        </span>
        <div className={sharingStyles.whoText}>
          <span className={sharingStyles.name}>{device.name}</span>
          <span className={sharingStyles.meta}>
            {device.current && <span className={`${sharingStyles.badge} ${sharingStyles.ok}`}>{t('devices.current')}</span>}
            <span>{platformLabel(device.platform)}</span>
            <span title={t('devices.signedIn', { date: formatDate(device.createdAt) })}>{t('devices.lastSeen', { date: formatRelative(device.lastSeenAt) })}</span>
          </span>
        </div>
      </div>
      <div className={sharingStyles.controls}>
        {device.current ? (
          name === undefined && (
            <Button variant="secondary" size="sm" icon="edit" onClick={() => setName(device.name)}>
              {t('common.rename')}
            </Button>
          )
        ) : (
          <Button variant="secondary" size="sm" icon="signOut" onClick={onSignOut} aria-label={t('devices.signOutWhat', { name: device.name })}>
            {t('devices.signOut')}
          </Button>
        )}
      </div>
      {name !== undefined && (
        <form className={sharingStyles.expand} onSubmit={rename}>
          <TextField label={t('devices.rename')} maxLength={64} autoFocus value={name} onChange={(e) => setName(e.target.value)} />
          <Button variant="secondary" size="sm" disabled={busy !== undefined} onClick={() => setName(undefined)}>
            {t('common.cancel')}
          </Button>
          <Button type="submit" size="sm" busy={busy === 'rename'} disabled={!name.trim()}>
            {t('common.save')}
          </Button>
        </form>
      )}
    </li>
  );
}
