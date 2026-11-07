import '@fontsource-variable/mona-sans/wdth.css';
import '@fontsource-variable/noto-sans-arabic/wght.css';
import '@fontsource/monaspace-neon/400.css';
import '@fontsource/monaspace-neon/600.css';
import '@octapass/ui/styles.css';
import '@octapass/web/src/app/app.css';
import { App } from '@octapass/web/src/app/App';
import { createAppRouter, routes as appRoutes } from '@octapass/web/src/app/routes';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { desktopPasskeyProvider, withPasskeyProvider } from './passkeyProvider';
import { PasskeyProviderSection } from './PasskeyProviderSection';
import { TauriVaultService } from './TauriVaultService';
import { tauriTransport } from './transport';
import { desktopBackground } from './background';
import { desktopSsh } from './ssh';
import { desktopWifi } from './wifi';

const transport = tauriTransport();
const service = await TauriVaultService.create(transport, { attachments: true, sharing: true, local: true, fillGate: true, autoType: true, files: true, wifi: await desktopWifi(transport), ssh: desktopSsh(transport), background: desktopBackground(transport) });

// The Windows 11 passkey section, from the app's package only: everywhere else it isn't added.
const passkeyProvider = await desktopPasskeyProvider(transport);
const router = createAppRouter(passkeyProvider ? withPasskeyProvider(appRoutes, <PasskeyProviderSection provider={passkeyProvider} />) : appRoutes);

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App service={service} router={router} />
  </StrictMode>,
);

// The app's own menus follow the language the vault shows (set on <html> by the settings).
const syncMenuLanguage = () => void transport.invoke('set_language', { language: document.documentElement.lang }).catch(() => {});
new MutationObserver(syncMenuLanguage).observe(document.documentElement, { attributes: true, attributeFilter: ['lang'] });
syncMenuLanguage();
