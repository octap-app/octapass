import '@fontsource-variable/mona-sans/wdth.css';
import '@fontsource-variable/noto-sans-arabic/wght.css';
import '@fontsource/monaspace-neon/400.css';
import '@octapass/ui/styles.css';
import { ServiceProvider } from '@octapass/web/src/app/ServiceContext';
import { loadSettings, SettingsProvider, STORAGE_KEY } from '@octapass/web/src/app/settings';
import { SiteIconsProvider } from '@octapass/web/src/lib/siteIcons';
import { applyLocale, resolveLocale } from '@octapass/web/src/i18n';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { TauriVaultService } from '../TauriVaultService';
import { tauriTransport } from '../transport';
import { QuickAccess, type AutoTypeOutcome, type QuickActions, type QuickOpened } from './QuickAccess';

const transport = tauriTransport();
const service = await TauriVaultService.create(transport);

const actions: QuickActions = {
  copy: async (id, field) => (await transport.invoke<{ clearsIn: number }>('copy_field', { id, field })).clearsIn,
  autoType: (id) => transport.invoke<AutoTypeOutcome>('auto_type', { id }),
  openAccessibilitySettings: () => void transport.invoke('open_accessibility_settings'),
  hide: () => void transport.invoke('hide_quick_access'),
  openVault: () => void transport.invoke('show_main_window'),
  onOpened: (cb) => {
    const stop = transport.listen<QuickOpened>('quick://opened', cb);
    return () => void stop.then((unlisten) => unlisten());
  },
};

const root = createRoot(document.getElementById('root')!);

// The language chosen in the vault window, which shares this window's storage.
function render(): void {
  const settings = loadSettings();
  const locale = resolveLocale(settings.language);
  applyLocale(locale);
  // Website icons follow the vault window's setting, and share its device cache.
  root.render(
    <StrictMode>
      <ServiceProvider service={service}>
        <SettingsProvider key={`${locale}:${settings.showSiteIcons}`}>
          <SiteIconsProvider>
            <QuickAccess service={service} actions={actions} />
          </SiteIconsProvider>
        </SettingsProvider>
      </ServiceProvider>
    </StrictMode>,
  );
}

render();
window.addEventListener('storage', (event) => event.key === STORAGE_KEY && render());
window.addEventListener('languagechange', render);
