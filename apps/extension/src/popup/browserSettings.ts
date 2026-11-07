// "Use Octa Pass instead of the browser's password manager": turns off the browser's own offers to save
// and fill passwords, addresses and cards through `chrome.privacy.services`, behind the optional
// `privacy` permission, asked for only when the user turns this on. Clearing our values gives the
// browser's own back, and Chrome clears them by itself when the extension is removed.
//
// Chrome and Edge expose all three; Firefox only `passwordSavingEnabled`; Safari has no `privacy` API,
// so the settings show the steps instead. Another extension or an enterprise policy may hold a
// setting (`levelOfControl`): that's reported, not treated as a failure.

export type BrowserFeature = 'passwords' | 'addresses' | 'cards';

export const BROWSER_FEATURES: BrowserFeature[] = ['passwords', 'addresses', 'cards'];

const SETTING_NAMES: Record<BrowserFeature, string> = {
  passwords: 'passwordSavingEnabled',
  addresses: 'autofillAddressEnabled',
  cards: 'autofillCreditCardEnabled',
};

/**
 * `off`: Octa Pass turned it off. `browser`: the browser's own setting, which Octa Pass can change.
 * `otherExtension` / `policy`: someone else holds it. `unsupported`: this browser doesn't let extensions change it.
 */
export type FeatureState = 'off' | 'browser' | 'otherExtension' | 'policy' | 'unsupported';

type LevelOfControl = 'not_controllable' | 'controlled_by_other_extensions' | 'controllable_by_this_extension' | 'controlled_by_this_extension';

export interface PrivacySetting {
  get(details: object): Promise<{ value: unknown; levelOfControl: LevelOfControl | string }>;
  set(details: { value: boolean }): Promise<void>;
  clear(details: object): Promise<void>;
}

export interface BrowserApis {
  /** `chrome.privacy`, read each time: it only appears once the permission is granted. */
  privacy(): { services?: Partial<Record<string, PrivacySetting>> } | undefined;
  permissions: {
    contains(permissions: { permissions: string[] }): Promise<boolean>;
    request(permissions: { permissions: string[] }): Promise<boolean>;
    remove(permissions: { permissions: string[] }): Promise<boolean>;
  };
  /** Whether the manifest lists `privacy` as optional (not on Safari). */
  optional: boolean;
  firefox: boolean;
}

/** What the user chose, in `chrome.storage.local`. */
export interface BrowserAutofillChoice {
  on: boolean;
  features: BrowserFeature[];
  /** The one-time suggestion after unlocking was shown and answered. */
  offered: boolean;
}

export const BROWSER_AUTOFILL_KEY = 'octapass:browserAutofill';
export const DEFAULT_CHOICE: BrowserAutofillChoice = { on: false, features: BROWSER_FEATURES, offered: false };

const PERMISSION = { permissions: ['privacy'] };

export function chromeApis(): BrowserApis {
  return {
    privacy: () => (chrome as Partial<typeof chrome>).privacy as ReturnType<BrowserApis['privacy']>,
    permissions: chrome.permissions as unknown as BrowserApis['permissions'],
    optional: (chrome.runtime.getManifest().optional_permissions ?? []).includes('privacy'),
    firefox: /Firefox\//.test(navigator.userAgent),
  };
}

/** The features this browser lets an extension change. Firefox only has the password one. */
export function supportedFeatures(apis: BrowserApis): BrowserFeature[] {
  if (!apis.optional) return [];
  const services = apis.privacy()?.services;
  if (services) return BROWSER_FEATURES.filter((f) => services[SETTING_NAMES[f]]);
  return apis.firefox ? ['passwords'] : BROWSER_FEATURES;
}

function stateOf(level: string, value: unknown): FeatureState {
  if (level === 'controlled_by_this_extension') return value === false ? 'off' : 'browser';
  if (level === 'controlled_by_other_extensions') return 'otherExtension';
  if (level === 'not_controllable') return 'policy';
  return 'browser';
}

/** Where each feature stands now. Without the permission nothing can be read, so it's the browser's. */
export async function readStates(apis: BrowserApis): Promise<Record<BrowserFeature, FeatureState>> {
  const supported = supportedFeatures(apis);
  const granted = supported.length > 0 && (await apis.permissions.contains(PERMISSION));
  const entries = await Promise.all(
    BROWSER_FEATURES.map(async (feature): Promise<[BrowserFeature, FeatureState]> => {
      if (!supported.includes(feature)) return [feature, 'unsupported'];
      const setting = granted ? apis.privacy()?.services?.[SETTING_NAMES[feature]] : undefined;
      if (!setting) return [feature, 'browser'];
      const { value, levelOfControl } = await setting.get({});
      return [feature, stateOf(levelOfControl, value)];
    }),
  );
  return Object.fromEntries(entries) as Record<BrowserFeature, FeatureState>;
}

/**
 * Asks for the permission. Call it first thing in a click handler: browsers only show the prompt for
 * a user gesture, and Firefox loses the gesture at the first `await`.
 */
export function requestPermission(apis: BrowserApis): Promise<boolean> {
  return apis.permissions.request(PERMISSION);
}

/** Turns the chosen features off in the browser and gives the others back. Settings someone else holds are left alone. */
export async function apply(apis: BrowserApis, features: BrowserFeature[]): Promise<Record<BrowserFeature, FeatureState>> {
  const services = apis.privacy()?.services;
  for (const feature of supportedFeatures(apis)) {
    const setting = services?.[SETTING_NAMES[feature]];
    if (!setting) continue;
    const { levelOfControl } = await setting.get({});
    if (levelOfControl !== 'controllable_by_this_extension' && levelOfControl !== 'controlled_by_this_extension') continue;
    if (features.includes(feature)) await setting.set({ value: false });
    else if (levelOfControl === 'controlled_by_this_extension') await setting.clear({});
  }
  return readStates(apis);
}

/** Gives every setting back to the browser and drops the permission. */
export async function restore(apis: BrowserApis): Promise<void> {
  if (!(await apis.permissions.contains(PERMISSION).catch(() => false))) return;
  await apply(apis, []);
  await apis.permissions.remove(PERMISSION).catch(() => false);
}

export async function loadChoice(): Promise<BrowserAutofillChoice> {
  const stored = (await chrome.storage.local.get(BROWSER_AUTOFILL_KEY))[BROWSER_AUTOFILL_KEY] as Partial<BrowserAutofillChoice> | undefined;
  return { ...DEFAULT_CHOICE, ...stored };
}

export async function saveChoice(choice: BrowserAutofillChoice): Promise<void> {
  await chrome.storage.local.set({ [BROWSER_AUTOFILL_KEY]: choice });
}

/** The browser's name, for "Use Octa Pass instead of Chrome's password manager". */
export function browserName(userAgent = navigator.userAgent): string {
  if (/Firefox\//.test(userAgent)) return 'Firefox';
  if (/Edg\//.test(userAgent)) return 'Edge';
  if (/Safari\//.test(userAgent) && !/Chrome\//.test(userAgent)) return 'Safari';
  return 'Chrome';
}
