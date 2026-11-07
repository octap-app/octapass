import '@fontsource-variable/mona-sans/wdth.css';
import '@fontsource-variable/noto-sans-arabic/wght.css';
import '@fontsource/monaspace-neon/400.css';
import '@fontsource/monaspace-neon/600.css';
import '@octapass/ui/styles.css';
import '@octapass/web/src/app/app.css';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { PopupApp } from './App';
import type { View } from './ExtensionContext';
import { connectVault } from './service';
import { startPath } from './startPath';
import { captureFromPage, returnAfterUnlock } from './useCurrentTab';

const params = new URLSearchParams(location.search);
const view: View = params.get('view') === 'window' ? 'window' : 'tab';
document.documentElement.dataset.view = view;
const tab = params.get('tab');
const tabId = tab ? Number(tab) : undefined;
// "Scan QR code on this page": the page the user was on, shown for a moment to read it.
const { service, api } = await connectVault(view === 'tab' ? { scanPage: (extension) => captureFromPage((id) => extension.scanTab(id)) } : {});
const initialPath = await startPath(service, params.get('path'), api);
// Opened by the inline menu's "Unlock": back to the page once the vault is open.
if (view === 'tab' && tabId !== undefined && params.get('back')) returnAfterUnlock(service, tabId);

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <PopupApp service={service} api={api} view={view} {...(tabId !== undefined ? { tabId } : {})} initialPath={initialPath} />
  </StrictMode>,
);
