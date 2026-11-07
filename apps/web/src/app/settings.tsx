import { createContext, Fragment, useCallback, useContext, useEffect, useMemo, useState, useSyncExternalStore, type ReactNode } from 'react';
import type { DeviceAuthSettings } from '@octapass/vault-client';
import { applyLocale, getLocale, resolveLocale, type LanguagePreference, type Locale } from '../i18n';

export type ThemePreference = 'system' | 'light' | 'dark';

export interface Settings extends DeviceAuthSettings {
  theme: ThemePreference;
  /** `system` follows the browser or system language. */
  language: LanguagePreference;
  /** Minutes of inactivity before the vault locks; 0 = only when the tab closes. */
  autoLockMinutes: number;
  /** Lock as soon as the tab is hidden. */
  lockOnHide: boolean;
  /** Website icons through the Octa Pass server; off sends no icon requests at all. */
  showSiteIcons: boolean;
  /** The apps: offer to save a network the device joins that isn't in the vault. */
  wifiOffers: boolean;
}

export const AUTO_LOCK_CHOICES = [1, 5, 15, 30, 60, 240, 0] as const;

const DEFAULTS: Settings = {
  theme: 'system',
  language: 'system',
  autoLockMinutes: 15,
  lockOnHide: false,
  showSiteIcons: true,
  wifiOffers: true,
  requireDeviceAuthOnAppOpen: true,
  requireDeviceAuthOnAutofill: true,
  requireDeviceAuthOnRevealCopy: true,
  requireReauthForCvv: false,
};
export const STORAGE_KEY = 'octapass:settings';

/**
 * Whether this app already kept settings when it started, read before anything writes them. These
 * settings are saved whole, so a lock time or "lock when hidden" at its default can't be told from
 * one the user picked.
 */
const SETTINGS_AT_START = (() => {
  try {
    return localStorage.getItem(STORAGE_KEY) !== null;
  } catch {
    return false;
  }
})();

/**
 * Plan 18's migration, for a device that hasn't decided "Stay unlocked" yet: a new install stays
 * unlocked; one that already kept settings keeps its lock, since the reading that doesn't relax a
 * lock the user may have picked wins (plan 18 History).
 */
export function stayUnlockedByDefault(): boolean {
  return !SETTINGS_AT_START;
}

/** Each language's name in that language, for the language choice. */
export const LANGUAGE_NAMES: Record<Locale, string> = { en: 'English', ar: 'العربية' };

// Preferences only, never vault data, so plain localStorage is fine.
export function loadSettings(): Settings {
  try {
    return { ...DEFAULTS, ...(JSON.parse(localStorage.getItem(STORAGE_KEY) ?? '{}') as Partial<Settings>) };
  } catch {
    return DEFAULTS;
  }
}

export function applyTheme(theme: ThemePreference): void {
  const root = document.documentElement;
  if (theme === 'system') root.removeAttribute('data-theme');
  else root.setAttribute('data-theme', theme);
}

interface SettingsContextValue {
  settings: Settings;
  update: (patch: Partial<Settings>) => void;
}

const SettingsContext = createContext<SettingsContextValue | null>(null);

export function SettingsProvider({ children }: { children: ReactNode }) {
  const [settings, setSettings] = useState(loadSettings);
  const languages = useSyncExternalStore(subscribeLanguages, systemLanguages, systemLanguages);
  const locale = resolveLocale(settings.language, languages ? languages.split(',') : undefined);
  // Before the children render, so the first frame is already in the right language and direction.
  if (getLocale() !== locale || document.documentElement.lang !== locale) applyLocale(locale);

  useEffect(() => {
    applyTheme(settings.theme);
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(settings));
    } catch {
      // Private browsing can refuse storage; the settings still apply for this visit.
    }
  }, [settings]);

  const update = useCallback((patch: Partial<Settings>) => setSettings((current) => ({ ...current, ...patch })), []);
  const value = useMemo(() => ({ settings, update }), [settings, update]);
  // Messages are read while rendering, so a new language renders every screen again from the start.
  return (
    <SettingsContext.Provider value={value}>
      <Fragment key={locale}>{children}</Fragment>
    </SettingsContext.Provider>
  );
}

function subscribeLanguages(onChange: () => void): () => void {
  window.addEventListener('languagechange', onChange);
  return () => window.removeEventListener('languagechange', onChange);
}

function systemLanguages(): string {
  return typeof navigator === 'undefined' ? '' : (navigator.languages ?? [navigator.language]).join(',');
}

export function useSettings(): SettingsContextValue {
  const value = useContext(SettingsContext);
  if (!value) throw new Error('useSettings must be used inside <SettingsProvider>');
  return value;
}
