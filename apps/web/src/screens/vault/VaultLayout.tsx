import { Icon } from '@octapass/ui';
import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react';
import { NavLink, Outlet, useLocation, useMatch, useNavigate } from 'react-router';
import { BackupReminder } from '../local/BackupReminder';
import { useService } from '../../app/ServiceContext';
import { useSettings } from '../../app/settings';
import { t } from '../../i18n';
import { HealthProvider } from '../../lib/health';
import { useAutoLock } from '../../lib/useAutoLock';
import { useStayUnlocked } from '../../lib/stayUnlocked';
import { useClientPolicies } from '../../lib/useOrganisation';
import { useMediaQuery } from '../../lib/useMediaQuery';
import { useShortcuts } from '../../lib/useShortcuts';
import { useLegacyWifiUpgrade } from '../../lib/wifi';
import { DeviceUnlockOffer } from './DeviceUnlockOffer';
import { ExtensionOffer } from './ExtensionOffer';
import { Sidebar } from './Sidebar';
import { WifiSaveOffer } from './Wifi';
import styles from './VaultLayout.module.css';

export interface VaultLayoutProps {
  /**
   * False where something else owns the lock timers: the extension's service worker locks the vault
   * for every page, and a tab in the background has no activity of its own to count.
   */
  lockTimers?: boolean;
  /** Passed to the sidebar: the host's own links above the vaults, and a card above Health (by default, the desktop app's offer of the extension). */
  sidebarTop?: ReactNode;
  sidebarBottom?: ReactNode;
}

export function VaultLayout({ lockTimers = true, sidebarTop, sidebarBottom }: VaultLayoutProps = {}) {
  const service = useService();
  const { settings } = useSettings();
  const navigate = useNavigate();
  const location = useLocation();
  const scope = useMatch('/items/:scope/*')?.params.scope;
  const [drawerOpen, setDrawerOpen] = useState(false);
  const narrow = useMediaQuery('(max-width: 1099px)');
  const sidebarRef = useRef<HTMLDivElement>(null);
  const opener = useRef<HTMLElement | null>(null);

  const openDrawer = useCallback(() => {
    opener.current = document.activeElement as HTMLElement | null;
    setDrawerOpen(true);
  }, []);
  const closeDrawer = useCallback(() => {
    setDrawerOpen(false);
    opener.current?.focus();
  }, []);

  // While open, the drawer behaves like a dialog: focus moves in and Escape closes it.
  useEffect(() => {
    if (!drawerOpen) return;
    const sidebar = sidebarRef.current;
    (sidebar?.querySelector<HTMLElement>('a[aria-current="page"]') ?? sidebar?.querySelector<HTMLElement>('a'))?.focus();
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') closeDrawer();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [drawerOpen, closeDrawer]);

  const lock = useCallback(() => service.lock(), [service]);
  // An organisation's limit wins over a longer choice, or "never", on this device.
  const { maxAutoLockMinutes } = useClientPolicies();
  const autoLock = maxAutoLockMinutes && (settings.autoLockMinutes === 0 || settings.autoLockMinutes > maxAutoLockMinutes) ? maxAutoLockMinutes : settings.autoLockMinutes;
  // Plan 18: staying unlocked, there's no lock timer and no lock when hidden. An organisation's
  // auto-lock limit wins over it: the switch goes off on this device (plan 18 History).
  const stay = useStayUnlocked();
  const stayOn = stay.status?.on === true;
  const setStay = stay.set;
  useEffect(() => {
    if (maxAutoLockMinutes && stayOn) void setStay(false).catch(() => undefined);
  }, [maxAutoLockMinutes, stayOn, setStay]);
  const staying = stay.active && !maxAutoLockMinutes;
  useAutoLock(lock, staying || !lockTimers ? 0 : autoLock, staying || !lockTimers ? false : settings.lockOnHide);
  useLegacyWifiUpgrade();

  useShortcuts({
    n: (event) => {
      event.preventDefault();
      const target = scope && scope !== 'trash' ? scope : 'all';
      navigate(`/items/${target}/new`);
    },
  });

  // Close the mobile drawer whenever the route changes.
  const [lastPath, setLastPath] = useState(location.pathname);
  if (lastPath !== location.pathname) {
    setLastPath(location.pathname);
    setDrawerOpen(false);
  }

  return (
    <HealthProvider>
      <div className={styles.shell} data-drawer={drawerOpen || undefined}>
        <a href="#main" className={styles.skip}>
          {t('nav.skipToContent')}
        </a>
        {/* Off-screen on small screens: inert keeps it out of the tab order and away from screen readers. */}
        <div ref={sidebarRef} className={styles.sidebar} inert={narrow && !drawerOpen}>
          <Sidebar onLock={lock} onClose={closeDrawer} top={sidebarTop} bottom={sidebarBottom ?? (service.browserExtension && <ExtensionOffer extension={service.browserExtension} />)} />
        </div>
        <div className={styles.scrim} onClick={closeDrawer} aria-hidden="true" />
        <main id="main" className={styles.main}>
          {service.local && <BackupReminder />}
          <Outlet context={{ openDrawer } satisfies LayoutContext} />
        </main>
        <nav className={styles.tabs} aria-label={t('nav.primary')}>
          <NavLink to="/items/all" className={({ isActive }) => (isActive || location.pathname.startsWith('/items') ? styles.tabOn : undefined)}>
            <Icon name="vault" size={22} />
            <span>{t('nav.items')}</span>
          </NavLink>
          <NavLink to="/generator" className={({ isActive }) => (isActive ? styles.tabOn : undefined)}>
            <Icon name="wand" size={22} />
            <span>{t('nav.generator')}</span>
          </NavLink>
          <NavLink to="/health" className={({ isActive }) => (isActive ? styles.tabOn : undefined)}>
            <Icon name="shield" size={22} />
            <span>{t('nav.health')}</span>
          </NavLink>
          <NavLink to="/settings" className={({ isActive }) => (isActive ? styles.tabOn : undefined)}>
            <Icon name="settings" size={22} />
            <span>{t('nav.settings')}</span>
          </NavLink>
        </nav>
      </div>
      {service.offerDeviceUnlock && <DeviceUnlockOffer />}
      {service.wifi && <WifiSaveOffer />}
    </HealthProvider>
  );
}

export interface LayoutContext {
  openDrawer: () => void;
}
