import { Icon, IconButton, type IconName } from '@octapass/ui';
import { isLocalServer, type Device } from '@octapass/vault-client';
import { useService, useSession } from '@octapass/web/src/app/ServiceContext';
import { useEffect, useState } from 'react';
import { tx } from '../i18n';
import { useExtension } from './ExtensionContext';
import styles from './GetApps.module.css';

/** Which offers the user closed, in `chrome.storage.local`. */
export const APPS_DISMISSED_KEY = 'octapass:apps-dismissed';

// No store listings yet: the platform pages say how to get each app (docs/platforms/).
const LINKS = {
  desktop: 'https://octap.app/docs/platforms/desktop/',
  mobile: 'https://octap.app/docs/platforms/mobile/',
} as const;

type App = keyof typeof LINKS;

const DESKTOPS = new Set(['mac', 'windows', 'linux', 'desktop']);
const PHONES = new Set(['ios', 'android']);

/** Which apps the account already has: its devices on the server, and the desktop app over native messaging. */
export function missingApps({ devices, desktopHere, safari, local }: { devices: Pick<Device, 'platform'>[] | undefined; desktopHere: boolean; safari: boolean; local: boolean }): App[] {
  const missing: App[] = [];
  // Safari's extension comes inside the Mac app, so that one is there already.
  const hasDesktop = safari || desktopHere || devices?.some((d) => DESKTOPS.has(d.platform));
  if (!hasDesktop) missing.push('desktop');
  // A vault on this device only can't reach a phone, and without the device list there's no telling.
  if (!local && devices && !devices.some((d) => PHONES.has(d.platform))) missing.push('mobile');
  return missing;
}

const COPY: Record<App, { icon: IconName; title: () => string; body: () => string }> = {
  desktop: { icon: 'monitor', title: () => tx('apps.desktopTitle'), body: () => tx('apps.desktopBody') },
  mobile: { icon: 'phone', title: () => tx('apps.mobileTitle'), body: () => tx('apps.mobileBody') },
};

/** A quiet card at the foot of the sidebar: the first Octa Pass app the account doesn't have yet. */
export function GetApps() {
  const service = useService();
  const session = useSession();
  const { api } = useExtension();
  const local = isLocalServer(session.serverUrl);
  const [missing, setMissing] = useState<App[]>();
  const [dismissed, setDismissed] = useState<Partial<Record<App, true>>>();

  useEffect(() => {
    let live = true;
    void chrome.storage.local.get(APPS_DISMISSED_KEY).then(
      (stored) => live && setDismissed((stored[APPS_DISMISSED_KEY] as Partial<Record<App, true>> | undefined) ?? {}),
      () => live && setDismissed({}),
    );
    const safari = chrome.runtime.getURL('').startsWith('safari-web-extension:');
    void Promise.all([
      // Running, or installed and refusing this browser: either way it's on this computer.
      Promise.resolve()
        .then(() => api.desktopStatus())
        .then((s) => s.appRunning || Boolean(s.browserNotTrusted), () => false),
      local || !service.sharing ? undefined : Promise.resolve().then(() => service.sharing!.listDevices()).catch(() => undefined),
    ]).then(([desktopHere, devices]) => live && setMissing(missingApps({ devices, desktopHere, safari, local })));
    return () => {
      live = false;
    };
  }, [api, service, local]);

  const app = missing?.find((one) => !dismissed?.[one]);
  if (!app || !dismissed) return null;

  const dismiss = () => {
    const next = { ...dismissed, [app]: true as const };
    setDismissed(next);
    void chrome.storage.local.set({ [APPS_DISMISSED_KEY]: next });
  };

  const copy = COPY[app];
  return (
    <aside className={styles.card} aria-labelledby="get-app-title">
      <span className={styles.icon} aria-hidden="true">
        <Icon name={copy.icon} size={18} />
      </span>
      <div className={styles.text}>
        <h2 id="get-app-title" className={styles.title}>
          {copy.title()}
        </h2>
        <p className={styles.body}>{copy.body()}</p>
        <a className={styles.link} href={LINKS[app]} target="_blank" rel="noopener noreferrer">
          {tx('apps.get')}
          <Icon name="external" size={14} />
        </a>
      </div>
      <IconButton icon="close" size="sm" label={tx('apps.dismiss')} className={styles.close} onClick={dismiss} />
    </aside>
  );
}
