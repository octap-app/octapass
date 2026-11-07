// The passkey prompt page. It loads only what the prompt draws: no web vault service, settings
// provider or web catalog (a vault error's message loads that when it's needed), and it renders
// its skeleton straight away instead of waiting for the service worker.

import '@fontsource-variable/mona-sans/wdth.css';
import '@fontsource-variable/noto-sans-arabic/wght.css';
import '@octapass/ui/styles.css';
import './page.css';
import { applyLocale, resolveLocale, type LanguagePreference } from '@octapass/web/src/i18n/core';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { passkeyClient } from './client';
import { linkFrame } from './frame';
import { Prompt } from './Prompt';

const requestId = location.hash.slice(1);
// First, so the content script's hello can't arrive before anyone listens.
const frame = window.parent !== window ? linkFrame(requestId) : undefined;

/** The web vault's settings key (apps/web/src/app/settings.tsx), which the extension's pages share. */
const SETTINGS_KEY = 'octapass:settings';

/** The theme and language the user chose in Octa Pass, before the first frame. */
function applySettings(): void {
  let settings: { theme?: unknown; language?: unknown } = {};
  try {
    settings = JSON.parse(localStorage.getItem(SETTINGS_KEY) ?? '{}') as typeof settings;
  } catch {
    // Unreadable storage: the system's theme and language.
  }
  if (settings.theme === 'light' || settings.theme === 'dark') document.documentElement.dataset.theme = settings.theme;
  const language = settings.language === 'en' || settings.language === 'ar' ? settings.language : 'system';
  applyLocale(resolveLocale(language as LanguagePreference));
}

applySettings();
const client = passkeyClient();

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <Prompt client={client} requestId={requestId} frame={frame} />
  </StrictMode>,
);
