import { Button, Checkbox, Dialog, Icon, IconButton, Select, Spinner, useToast } from '@octapass/ui';
import {
  hasPassword,
  inRangeFirst,
  isEnterprise,
  signalBars,
  wifiDraft,
  wifiQrText,
  wifiSsid,
  type DeviceWifiNetwork,
  type Item,
  type ItemSummary,
  type WifiDetails,
  type WifiService,
  type WifiSighting,
} from '@octapass/vault-client';
import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router';
import { DEFAULT_SERVER_URL } from '../../app/service';
import { useService, useSession } from '../../app/ServiceContext';
import { useSettings } from '../../app/settings';
import { Alert } from '../../components/Alert';
import { QrCode } from '../../components/QrCode';
import { t, type MessageKey } from '../../i18n';
import { useCopy } from '../../lib/clipboard';
import { errorMessage } from '../../lib/errors';
import { shareLinkUrl } from '../../lib/shareLinks';
import { useSharing } from '../../lib/useSharing';
import { useItems, useVaults } from '../../lib/useItems';
import { loadOffers, saveOffers, setPendingDraft, useWifiRadar, type WifiRadarState } from '../../lib/wifi';
import { Field, FieldList, SecretField } from './Fields';
import { PasswordHistory } from './ItemDetail';
import styles from './Wifi.module.css';

const phone = (wifi: WifiService | undefined) => wifi?.platform === 'ios' || wifi?.platform === 'android';

/** Signal strength as four bars, the way the system draws it. */
export function SignalBars({ signal }: { signal: number }) {
  const bars = signalBars(signal);
  return (
    <svg className={styles.bars} viewBox="0 0 16 12" width={16} height={12} role="img" aria-label={t('wifi.signal', { bars })}>
      {[0, 1, 2, 3].map((i) => (
        <rect key={i} x={i * 4} y={9 - i * 3} width={3} height={3 + i * 3} rx={0.75} className={i < bars ? styles.barOn : styles.barOff} />
      ))}
    </svg>
  );
}

/** "Connected", or "In range" with the signal, for a network the device is on or sees. */
export function WifiMark({ ssid, radar }: { ssid: string | undefined; radar: Pick<WifiRadarState, 'connected' | 'sightings'> | undefined }) {
  if (!ssid || !radar) return null;
  if (radar.connected === ssid) {
    return (
      <span className={[styles.mark, styles.connected].join(' ')}>
        <Icon name="wifi" size={13} />
        {t('wifi.connected')}
      </span>
    );
  }
  const sighting = radar.sightings.get(ssid);
  if (!sighting) return null;
  return (
    <span className={styles.mark}>
      <SignalBars signal={sighting.signal} />
      {t('wifi.inRange')}
    </span>
  );
}

/** Asks for location access (the system's dialog) or says it's off: phones and Macs tell apps network names only with it. */
export function WifiPermissionNote({ radar }: { radar: NonNullable<ReturnType<typeof useWifiRadar>> }) {
  if (radar.permission === 'prompt') {
    return (
      <Alert
        tone="info"
        action={
          <Button size="sm" onClick={radar.requestPermission}>
            {t('wifi.permissionAllow')}
          </Button>
        }
      >
        <strong>{t('wifi.permissionTitle')}</strong> {radar.wifi.features.nearby ? t('wifi.permissionBody') : t('wifi.permissionBodyCurrent')}
      </Alert>
    );
  }
  if (radar.permission === 'denied') return <Alert tone="warn">{t('wifi.permissionDenied')}</Alert>;
  return null;
}

/** The Wi-Fi list's own buttons: look again, and bring networks in from the device. */
export function WifiListTools({ radar }: { radar: ReturnType<typeof useWifiRadar> }) {
  const [importing, setImporting] = useState(false);
  if (!radar) return null;
  const canLook = radar.permission === 'granted' && (radar.wifi.features.nearby || radar.wifi.features.current);
  return (
    <>
      {canLook && <IconButton icon="refresh" label={t('wifi.refresh')} disabled={radar.scanning} onClick={radar.refresh} />}
      <IconButton icon="download" label={t('wifi.importAction')} onClick={() => setImporting(true)} />
      {importing && (radar.wifi.features.savedNetworks ? <WifiImportDialog wifi={radar.wifi} onClose={() => setImporting(false)} /> : <PhoneImportDialog wifi={radar.wifi} onClose={() => setImporting(false)} />)}
    </>
  );
}

function yes(flag: boolean | undefined) {
  return flag ? t('wifi.yes') : undefined;
}

/** A one-time link for one guest for a day: the QR holds the link, not the network, and the item stays yours. */
function GuestLink({ item }: { item: Item }) {
  const sharing = useSharing();
  const session = useSession();
  const copy = useCopy();
  const [url, setUrl] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  if (!sharing) return null;

  async function create() {
    setBusy(true);
    setError(undefined);
    try {
      const link = await sharing!.createShareLink(item.id, { expiresInHours: 24, maxViews: 1 });
      setUrl(link.url ?? shareLinkUrl(window.location.origin, link, session.serverUrl ?? DEFAULT_SERVER_URL, DEFAULT_SERVER_URL));
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      {!url && (
        <Button variant="secondary" size="sm" icon="link" busy={busy} onClick={() => void create()}>
          {t('wifi.guestAction')}
        </Button>
      )}
      {error && <Alert>{error}</Alert>}
      {url && (
        <>
          <QrCode value={url} size={200} label={t('wifi.guestQrLabel')} />
          <p>{t('wifi.guestHelp')}</p>
          <Button variant="secondary" size="sm" icon="copy" onClick={() => void copy(url, t('shareLink.linkWhat'))}>
            {t('shareLink.copyLink')}
          </Button>
        </>
      )}
    </>
  );
}

/** `live`: the item itself in the vault, not a shared copy of it. */
export function WifiFields({ item, live = false }: { item: Item; live?: boolean }) {
  const details = item.details as WifiDetails;
  const wifi = useService().wifi;
  const radar = useWifiRadar(true);
  const [showQr, setShowQr] = useState(false);
  const enterprise = isEnterprise(details.security);
  // Phones show their own QR sheet, at full brightness.
  const qr = !phone(wifi) ? wifiQrText(details) : undefined;
  return (
    <>
      {radar && <WifiPermissionNote radar={radar} />}
      <FieldList>
        <Field label={t('wifi.ssid')} value={details.ssid} secret={false}>
          <span className={styles.ssid}>
            <bdi>{details.ssid}</bdi>
            <WifiMark ssid={details.ssid} radar={radar} />
          </span>
        </Field>
        {hasPassword(details.security) ? <SecretField label={t('fields.password')} value={details.password} /> : <Field label={t('fields.password')} value={t('wifi.noPassword')} copy={false} />}
        <Field label={t('wifi.security')} value={t(`wifi.securities.${details.security}` as MessageKey) || details.security} copy={false} />
        <Field label={t('wifi.hidden')} value={yes(details.hidden)} copy={false} />
      </FieldList>

      {enterprise && (
        <FieldList title={t('wifi.enterprise')}>
          <Field label={t('wifi.eapMethod')} value={details.eapMethod && t(`wifi.eapMethods.${details.eapMethod}` as MessageKey)} copy={false} />
          <Field label={t('wifi.phase2')} value={details.phase2 && t(`wifi.phase2s.${details.phase2}` as MessageKey)} copy={false} />
          <Field label={t('fields.username')} value={details.username} secret={false} />
          <Field label={t('wifi.identity')} value={details.identity} secret={false} />
          <Field label={t('wifi.serverDomain')} value={details.serverDomain} secret={false} ltr />
          <Field label={t('wifi.caCertificate')} value={details.caCertificate} secret={false} mono multiline />
        </FieldList>
      )}

      {(details.captivePortal || details.managed || details.hotspot) && (
        <FieldList title={t('wifi.about')}>
          <Field label={t('wifi.captivePortal')} value={yes(details.captivePortal)} copy={false} />
          <Field label={t('wifi.managed')} value={yes(details.managed)} copy={false} />
          <Field label={t('wifi.hotspot')} value={yes(details.hotspot)} copy={false} />
        </FieldList>
      )}

      {qr && (
        <section className={styles.qr}>
          <Button variant="secondary" size="sm" icon={showQr ? 'eyeOff' : 'eye'} aria-expanded={showQr} onClick={() => setShowQr((s) => !s)}>
            {showQr ? t('wifi.qrHide') : t('wifi.qrShow')}
          </Button>
          {showQr && (
            <>
              <QrCode value={qr} size={200} label={t('wifi.qrLabel', { ssid: details.ssid })} />
              <p>{t('wifi.qrHelp')}</p>
            </>
          )}
          {live && !item.deletedAt && <GuestLink item={item} />}
        </section>
      )}

      {details.customFields && details.customFields.length > 0 && (
        <FieldList title={t('detail.moreFields')}>
          {details.customFields.map((field, i) =>
            field.hidden ? <SecretField key={i} label={field.label} value={field.value} /> : <Field key={i} label={field.label} value={field.value} secret={false} />,
          )}
        </FieldList>
      )}

      {details.notes && (
        <FieldList title={t('fields.notes')}>
          <Field label={t('fields.notes')} value={details.notes} multiline secret />
        </FieldList>
      )}

      {details.passwordHistory && details.passwordHistory.length > 0 && <PasswordHistory history={details.passwordHistory} />}
    </>
  );
}

// ---------- Importing the device's saved networks ----------

/** The network names already in the vault. */
function useSavedSsids(): Set<string> | undefined {
  const { items } = useItems({ type: 'wifi' });
  return useMemo(() => (items ? new Set(items.map(wifiSsid).filter((s): s is string => Boolean(s))) : undefined), [items]);
}

/**
 * Brings the computer's saved networks in, in one batch the user picks from first. The system asks
 * before it gives each password (macOS: an administrator's name and password, in its own window).
 */
export function WifiImportDialog({ wifi, onClose }: { wifi: WifiService; onClose: () => void }) {
  const service = useService();
  const toast = useToast();
  const vaults = useVaults();
  const saved = useSavedSsids();
  const [networks, setNetworks] = useState<DeviceWifiNetwork[]>();
  const [loadError, setLoadError] = useState<string>();
  const [chosen, setChosen] = useState<Set<string>>(new Set());
  const [vaultId, setVaultId] = useState<string>();
  const [busy, setBusy] = useState(false);
  const writable = (vaults ?? []).filter((v) => v.role !== 'read' && !v.untrusted);
  const target = vaultId ?? writable.find((v) => v.type === 'personal')?.id ?? writable[0]?.id;

  useEffect(() => {
    let live = true;
    void (wifi.savedNetworks?.() ?? Promise.resolve([])).then(
      (list) => live && setNetworks(list),
      (error: unknown) => live && setLoadError(errorMessage(error)),
    );
    return () => {
      live = false;
    };
  }, [wifi]);

  // Networks not in the vault yet start chosen.
  useEffect(() => {
    if (networks && saved) setChosen(new Set(networks.filter((n) => !saved.has(n.ssid)).map((n) => n.ssid)));
  }, [networks, saved]);

  const toggle = (ssid: string, on: boolean) =>
    setChosen((current) => {
      const next = new Set(current);
      if (on) next.add(ssid);
      else next.delete(ssid);
      return next;
    });

  async function importChosen() {
    if (!target || !networks) return;
    setBusy(true);
    try {
      const names = networks.filter((n) => chosen.has(n.ssid)).map((n) => n.ssid);
      const read = await (wifi.readSavedPasswords?.(names) ?? Promise.resolve([]));
      const byName = new Map(read.map((n) => [n.ssid, n]));
      let imported = 0;
      let withoutPassword = 0;
      for (const ssid of names) {
        const network = { ...networks.find((n) => n.ssid === ssid), ...byName.get(ssid), ssid };
        const security = network.security ?? (network.password ? 'wpa2' : 'open');
        if (hasPassword(security) && !isEnterprise(security) && !network.password) withoutPassword++;
        await service.saveItem(wifiDraft({ ssid, security, ...(network.password ? { password: network.password } : {}), ...(network.hidden ? { hidden: true } : {}) }, target));
        imported++;
      }
      toast({ message: [t('wifi.importDone', { count: imported }), withoutPassword ? t('wifi.importNoPassword', { count: withoutPassword }) : ''].filter(Boolean).join(' '), tone: 'success' });
      onClose();
    } catch (error) {
      toast({ message: errorMessage(error), tone: 'danger' });
      setBusy(false);
    }
  }

  const prompt = wifi.platform === 'mac' ? t('wifi.importMac') : wifi.platform === 'windows' ? t('wifi.importWindows') : t('wifi.importLinux');
  return (
    <Dialog
      open
      onClose={busy ? () => {} : onClose}
      closeLabel={t('common.close')}
      title={t('wifi.importTitle')}
      size="md"
      footer={
        <>
          <Button variant="secondary" onClick={onClose} disabled={busy}>
            {t('common.cancel')}
          </Button>
          <Button onClick={() => void importChosen()} busy={busy} disabled={chosen.size === 0 || !target}>
            {busy ? t('wifi.importReading') : t('wifi.importSelected', { count: chosen.size })}
          </Button>
        </>
      }
    >
      <div className={styles.import}>
        <p>{t('wifi.importIntro')}</p>
        <Alert tone="info">{prompt}</Alert>
        {loadError ? (
          <Alert>{t('wifi.importFailed')}</Alert>
        ) : !networks || !saved ? (
          <p className={styles.loading}>
            <Spinner size={16} /> {t('wifi.importLoading')}
          </p>
        ) : networks.length === 0 ? (
          <p>{t('wifi.importNone')}</p>
        ) : (
          <>
            <div className={styles.importActions}>
              <Button variant="ghost" size="sm" onClick={() => setChosen(new Set(networks.map((n) => n.ssid)))}>
                {t('wifi.selectAll')}
              </Button>
              <Button variant="ghost" size="sm" onClick={() => setChosen(new Set())}>
                {t('wifi.selectNone')}
              </Button>
            </div>
            <ul className={styles.networks}>
              {networks.map((network) => (
                <li key={network.ssid}>
                  <Checkbox label={<bdi>{network.ssid}</bdi>} checked={chosen.has(network.ssid)} onChange={(e) => toggle(network.ssid, e.target.checked)} />
                  {saved.has(network.ssid) && <small>{t('wifi.importAlready')}</small>}
                </li>
              ))}
            </ul>
            {writable.length > 1 && <Select label={t('wifi.importVault')} value={target} onChange={(e) => setVaultId(e.target.value)} options={writable.map((v) => ({ value: v.id, label: v.name }))} />}
          </>
        )}
      </div>
    </Dialog>
  );
}

/** Phones can't read saved networks: says so, and how to bring one in instead. */
function PhoneImportDialog({ wifi, onClose }: { wifi: WifiService; onClose: () => void }) {
  return (
    <Dialog
      open
      onClose={onClose}
      closeLabel={t('common.close')}
      title={t('wifi.phoneImportTitle')}
      footer={<Button onClick={onClose}>{t('common.close')}</Button>}
    >
      <p>{wifi.platform === 'ios' ? t('wifi.iosImport') : t('wifi.androidImport')}</p>
    </Dialog>
  );
}

// ---------- "Save this network?" ----------

/**
 * Offers to keep a network the device is on that isn't in the vault: when the computer joins one
 * (with its password from the system), or when the phone app opens on one (the user types the
 * password). Once per network; never again after "Never for this network"; off in Settings.
 */
export function WifiSaveOffer() {
  const service = useService();
  const wifi = service.wifi;
  const navigate = useNavigate();
  const { settings } = useSettings();
  const saved = useSavedSsids();
  const vaults = useVaults();
  const [ssid, setSsid] = useState<string>();
  const [busy, setBusy] = useState(false);
  const enabled = Boolean(wifi && settings.wifiOffers && (wifi.features.joins || wifi.features.current));

  useEffect(() => {
    if (!wifi || !enabled) return;
    // The latest network wins: the offer is about where the device is now.
    const consider = (name: string | undefined) => name && setSsid(name);
    // Computers say when they join; phones are checked when the app opens or comes back.
    const unsubscribe = wifi.onJoin?.(consider);
    const check = () => {
      if (document.visibilityState === 'hidden') return;
      void wifi.permission().then((p) => (p === 'granted' ? wifi.currentNetwork().then(consider) : undefined)).catch(() => {});
    };
    if (phone(wifi)) {
      check();
      document.addEventListener('visibilitychange', check);
    }
    return () => {
      unsubscribe?.();
      document.removeEventListener('visibilitychange', check);
    };
  }, [wifi, enabled]);

  const offers = loadOffers();
  const show = Boolean(enabled && ssid && saved && !saved.has(ssid) && !offers.never.includes(ssid) && !offers.asked.includes(ssid));
  if (!wifi || !ssid || !show) return null;

  const done = (never: boolean) => {
    const current = loadOffers();
    saveOffers({ asked: [...new Set([...current.asked, ssid])], never: never ? [...new Set([...current.never, ssid])] : current.never });
    setSsid(undefined);
  };

  async function save() {
    if (!wifi || !ssid) return;
    setBusy(true);
    const writable = (vaults ?? []).filter((v) => v.role !== 'read' && !v.untrusted);
    const vaultId = writable.find((v) => v.type === 'personal')?.id ?? writable[0]?.id;
    let network: DeviceWifiNetwork = { ssid };
    if (wifi.readSavedPasswords) network = (await wifi.readSavedPasswords([ssid]).catch(() => []))[0] ?? network;
    setBusy(false);
    done(false);
    if (!vaultId) return;
    const security = network.security ?? (network.password || !wifi.readSavedPasswords ? 'wpa2' : 'open');
    setPendingDraft(wifiDraft({ ssid, security, ...(network.password ? { password: network.password } : {}), ...(network.hidden ? { hidden: true } : {}) }, vaultId));
    navigate('/items/wifi/new?type=wifi');
  }

  return (
    <aside className={styles.offer} aria-labelledby="wifi-offer-title" role="status">
      <Icon name="wifi" size={22} className={styles.offerIcon} />
      <div className={styles.offerText}>
        <p id="wifi-offer-title" className={styles.offerTitle}>
          {t('wifi.offerTitle', { ssid })}
        </p>
        <p>{wifi.readSavedPasswords ? t('wifi.offerComputer') : t('wifi.offerPhone')}</p>
        <div className={styles.offerActions}>
          <Button size="sm" busy={busy} onClick={() => void save()}>
            {t('wifi.offerSave')}
          </Button>
          <Button size="sm" variant="secondary" onClick={() => done(false)}>
            {t('wifi.offerNotNow')}
          </Button>
          <Button size="sm" variant="ghost" onClick={() => done(true)}>
            {t('wifi.offerNever')}
          </Button>
        </div>
      </div>
    </aside>
  );
}

/** The networks in range, the connected one first and then by signal, apart from the rest of the Wi-Fi list. */
export function nearbyFirst(items: ItemSummary[], radar: { connected?: string; sightings: ReadonlyMap<string, WifiSighting> } | undefined): { nearby: ItemSummary[]; rest: ItemSummary[] } {
  if (!radar) return { nearby: [], rest: items };
  const near = (item: ItemSummary) => {
    const ssid = wifiSsid(item);
    return Boolean(ssid && (ssid === radar.connected || radar.sightings.has(ssid)));
  };
  return { nearby: inRangeFirst(items.filter(near), radar.sightings, radar.connected), rest: items.filter((item) => !near(item)) };
}
