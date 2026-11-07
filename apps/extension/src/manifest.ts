// The Manifest V3 manifest for each browser. Chrome and Edge run the background as a service worker;
// Firefox runs the same module as a background script. Safari runs the service worker too, packaged
// inside the apps in apps/safari. The toolbar button has no popup: the background opens the app page
// in a tab (background/appTab.ts).

export type Target = 'chrome' | 'firefox' | 'safari';

/** Placeholder until the add-on is listed on AMO; it must never change after that. The desktop app's native messaging manifest allows it. */
export const GECKO_ID = 'extension@octap.app';

/**
 * The development public key: it pins the unpacked Chrome extension's ID to
 * `oojckfebkmiogiahdggohbdnndbfcjnm`, which the desktop app's native messaging manifest allows and
 * passkey device unlock needs to stay stable (plan 13, J). Store builds leave it out: the store
 * assigns the ID.
 */
export const DEV_KEY =
  'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1uWtUvUHG17WaPiX0tb5DtCoVisp10Nh1dgaUkbG/KnhDpq3o1mgX0/7dN2OY5SdxkQBISjj90WZVtennteu5MjnMRKESNU7/l7gQENm/Uva9wjRfJm9OyC5IJ/WPIp15yiw2UkUS1ZdRR0iBrmnDNkqVZlHu1mWCug/JTH1hB8iLRZ2OV/TPI2omdsF4A3H3loUjV/hEzgtc2CprZMPk6nUmCs4TJ5l5+bsojta+VwRd5uj2VPRBP0SuETXJuGr/gKQRWRy0xoLJDfj7+bZRk1p5Ij0ifGyiFtal+SPNvhEKyC96s07kkqiphB68UWXTDBvOjSgf8VFqfw8OihxxQIDAQAB';

const WEB_PAGES = ['http://*/*', 'https://*/*'];
const ICONS = { 16: 'icons/icon-16.png', 32: 'icons/icon-32.png', 48: 'icons/icon-48.png', 128: 'icons/icon-128.png' };

export function createManifest(target: Target, version: string, { store = false } = {}): chrome.runtime.ManifestV3 {
  const common = {
    manifest_version: 3,
    name: 'Octa Pass',
    short_name: 'Octa Pass',
    version,
    description: 'Free, open-source and end-to-end encrypted password manager.',
    icons: ICONS,
    action: { default_title: 'Octa Pass', default_icon: ICONS },
    // The service worker reaches the sync server and every content script needs the pages it fills.
    // `activeTab` and `contextMenus` (permissions below): reading a QR code from a page's screenshot,
    // and the "Add one-time code from QR" menu on images. `webRequest` and `webRequestAuthProvider`:
    // answering HTTP Basic and Digest sign-in prompts, which Safari doesn't offer.
    host_permissions: WEB_PAGES,
    content_scripts: [
      { matches: WEB_PAGES, js: ['content.js'], run_at: 'document_start', all_frames: true },
      // Wraps navigator.credentials for passkeys. It has to run in the page's own JavaScript world.
      { matches: WEB_PAGES, js: ['page.js'], run_at: 'document_start', all_frames: true, world: 'MAIN' },
    ],
    // The WASM core is compiled at run time, which MV3 only allows with `wasm-unsafe-eval`.
    content_security_policy: { extension_pages: "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'" },
    // The passkey prompt is an extension page framed by the website, so the website can't script it.
    web_accessible_resources: [{ resources: ['passkey.html', 'assets/*'], matches: WEB_PAGES }],
  } satisfies Partial<chrome.runtime.ManifestV3>;

  if (target === 'safari') {
    return {
      ...common,
      // Safari has no `idle`, and its native messaging only reaches the containing app, not the
      // desktop app's host.
      permissions: ['storage', 'alarms', 'activeTab', 'contextMenus'],
      background: { service_worker: 'background.js', type: 'module' },
      // 18: `world: "MAIN"` content scripts, for the passkey wrapper.
      browser_specific_settings: { safari: { strict_min_version: '18.0' } },
    } as unknown as chrome.runtime.ManifestV3;
  }
  if (target === 'chrome') {
    return {
      ...common,
      // 133: X25519 in WebCrypto, for unlocking through the desktop app.
      minimum_chrome_version: '133',
      permissions: ['storage', 'alarms', 'idle', 'nativeMessaging', 'activeTab', 'contextMenus', 'webRequest', 'webRequestAuthProvider'],
      // Asked for when the user chooses Octa Pass over the browser's own password manager.
      optional_permissions: ['privacy'],
      ...(store ? {} : { key: DEV_KEY }),
      background: { service_worker: 'background.js', type: 'module' },
    } as chrome.runtime.ManifestV3;
  }
  return {
    ...common,
    permissions: ['storage', 'alarms', 'idle', 'nativeMessaging', 'activeTab', 'contextMenus', 'webRequest', 'webRequestAuthProvider'],
    optional_permissions: ['privacy'],
    background: { scripts: ['background.js'], type: 'module' },
    browser_specific_settings: {
      // 130: X25519 in WebCrypto (MAIN-world content scripts came in 128).
      gecko: { id: GECKO_ID, strict_min_version: '130.0', data_collection_permissions: { required: ['none'] } },
    },
  } as unknown as chrome.runtime.ManifestV3;
}
