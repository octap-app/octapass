// Single source of truth for public URLs.
// Override with PUBLIC_* environment variables for a fork or a preview build.
export const SITE_URL = process.env.PUBLIC_SITE_URL ?? 'https://octap.app';
export const REPO_URL = process.env.PUBLIC_REPO_URL ?? 'https://github.com/octap-app/octapass';
export const SITE_NAME = 'Octa Pass';
export const SITE_TAGLINE = 'The free password manager for every login, passkey and code you own.';
export const SITE_DESCRIPTION =
  'Octa Pass is a free password manager for passwords, passkeys, one-time codes, cards and identities on every browser, phone and computer. End-to-end encrypted, synced for you, no ads. Open source, so anyone can check it.';

// The hosted service: sync server and web vault on one origin. Open for sign-ups as a public alpha.
export const VAULT_URL = process.env.PUBLIC_VAULT_URL ?? 'https://vault.octap.app';

/** The platforms on the landing page. Each has a matching item (same `id`) in src/i18n/landing/*.json. */
export type PlatformId =
  | 'web'
  | 'chromium'
  | 'firefox'
  | 'safari'
  | 'mac'
  | 'windows'
  | 'linux'
  | 'ios'
  | 'android'
  | 'cli'
  | 'vscode'
  | 'jetbrains';

/**
 * Where to get each app. Every entry is `null` until the app is published; set it to the listing's URL and the
 * landing page shows a "Get it" link instead of "Coming soon". This is the only place store links live.
 * The web vault isn't here: it's VAULT_URL, and it's available now.
 */
export const STORE_LINKS: Record<Exclude<PlatformId, 'web'>, string | null> = {
  chromium: null, // Chrome Web Store (Edge and Brave install from it too)
  firefox: null, // Firefox Add-ons
  safari: null, // App Store / Mac App Store (the Safari extension ships inside its own app)
  mac: null, // Mac App Store
  windows: null, // Microsoft Store, or a download page
  linux: null, // Flathub, or a download page
  ios: null, // App Store
  android: null, // Google Play
  cli: null, // Homebrew, or a download page
  vscode: null, // Visual Studio Code Marketplace
  jetbrains: null, // JetBrains Marketplace
};

/** Each platform's source folder in the monorepo, linked from the landing page as `${REPO_URL}/tree/main/<path>`. */
export const SOURCE_PATHS: Record<PlatformId, string> = {
  web: 'apps/web',
  chromium: 'apps/extension',
  firefox: 'apps/extension',
  safari: 'apps/safari',
  mac: 'apps/macos',
  windows: 'apps/desktop',
  linux: 'apps/desktop',
  ios: 'apps/ios',
  android: 'apps/android',
  cli: 'apps/cli',
  vscode: 'apps/vscode',
  jetbrains: 'apps/jetbrains',
};

export const isPlatformId = (id: string): id is PlatformId => id in SOURCE_PATHS;

/** Where a platform's app can be had today: the web vault, a store listing, or nowhere yet. */
export function platformLink(id: PlatformId): { href: string; kind: 'open' | 'store' } | null {
  if (id === 'web') return { href: VAULT_URL, kind: 'open' };
  const href = STORE_LINKS[id];
  return href ? { href, kind: 'store' } : null;
}

export const repoTree = (path: string) => `${REPO_URL}/tree/main/${path}`;
export const repoFile = (path: string) => `${REPO_URL}/blob/main/${path}`;
