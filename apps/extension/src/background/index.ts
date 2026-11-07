// The service worker (Chrome, Edge) or background script (Firefox). Listeners are registered at the
// top level, as MV3 requires for events that wake the worker; each one waits for the vault to load.

import init, * as coreModule from '@octapass/core/full';
import wasmUrl from '@octapass/core/full/octapass_core_bg.wasm?url';
import type { BackupSecret } from '@octapass/core/full';
import type { StayUnlockedStatus } from '@octapass/vault-client';
import type { Core } from '@octapass/vault-client/remote';
import { describeBrowser } from '@octapass/vault-client/remote/worker';
import { resolveLocale, setLocale, type LanguagePreference } from '@octapass/web/src/i18n/core';
import { LANGUAGE_KEY, tx } from '../i18n';
import type { ContentRequest, FillMessage, WebsiteAnswer, WebsitePrompt } from '../shared/messages';
import { WebsiteAdder } from './addWebsite';
import { PASSKEY_PORT, type PasskeyPortMessage } from '../shared/passkey';
import { postEvent, serveRpc, UI_PORT, type Handlers } from '../shared/rpc';
import { AutoLock, LOCK_SETTINGS_KEY, readLockSettings, type LockSettings } from './autoLock';
import { ApiKeySaver } from './apiKeys';
import { handleContent, loginFillValues, otherLoginFillValues } from './content';
import { DesktopLink, NATIVE_HOST } from './desktop';
import { AutofillAuth } from './deviceAuth';
import { FrameApprovals } from './frames';
import { SaveInbox } from './inbox';
import { HttpAuth, type AuthAnswer, type AuthChallenge } from './httpAuth';
import { Matcher } from './matching';
import { PasskeyRequests, parseCall } from './passkeyRequests';
import { PasskeyAuthenticator } from './passkeys';
import { PendingScans, scanImage, scanTab, type QrReader } from './qr';
import { MaskedEmailFiller } from './maskedEmail';
import { DetailsSaver } from './detailsSaves';
import { NeverSave, type SaveKind } from './neverSave';
import { LoginSaver } from './saves';
import { DEFAULT_SERVER_URL } from '../popup/webService';
import { SiteIcons, siteIconsEnabled } from './siteIcons';
import { APP_PAGE, chromeAppTabApis, openApp, type OpenAppOptions } from './appTab';
import { isExtensionPage, pageSender } from './senders';
import { openKeyValueStore, storageArea } from './storage';
import { PAGE_METHODS, VaultHost } from './vault';

// The full WASM build: the web vault's lacks local vaults (they need zxcvbn for the password check).
let core: Promise<typeof coreModule> | undefined;
const loadFull = () => (core ??= init({ module_or_path: wasmUrl }).then(() => coreModule));
const loadCore = loadFull as unknown as () => Promise<Core>;

/** Chrome stops an idle worker after 30 s; a local vault can't come back from that, so it keeps it awake. */
const KEEPALIVE_MS = 20_000;
let keepalive: ReturnType<typeof setInterval> | undefined;
function keepAwake(on: boolean): void {
  if (on) keepalive ??= setInterval(() => void chrome.runtime.getPlatformInfo(), KEEPALIVE_MS);
  else {
    clearInterval(keepalive);
    keepalive = undefined;
  }
}

let promptKeepalive: ReturnType<typeof setInterval> | undefined;
let fillKeepalive: ReturnType<typeof setInterval> | undefined;

const memory = storageArea(chrome.storage.session);
const desktop = new DesktopLink((message) => chrome.runtime.sendNativeMessage(NATIVE_HOST, message));
const autoLock = new AutoLock({
  memory,
  alarms: chrome.alarms,
  lock: () => void ready.then(({ host }) => host.lock()),
  // Staying unlocked (plan 18), a computer lock only resets "revealing asked once".
  onDeviceLock: () => void ready.then(({ host }) => host.resetConfirmed()),
});

const ready = (async () => {
  const disk = await openKeyValueStore('octapass');
  const settings = (await chrome.storage.local.get(LOCK_SETTINGS_KEY))[LOCK_SETTINGS_KEY] as Partial<LockSettings> | undefined;
  await autoLock.configure(settings);
  const host = await VaultHost.start(
    { loadCore: loadFull, disk, memory, device: { name: `${describeBrowser(navigator.userAgent)} extension`, platform: 'extension' }, chip: (vaultId, context) => desktop.chipSecret(vaultId, context) },
    () => autoLock.expired(),
  );
  const matcher = new Matcher(await loadFull());
  const frames = new FrameApprovals(await openKeyValueStore('octapass-frames'), matcher);
  const httpAuth = new HttpAuth(host, await openKeyValueStore('octapass-http-auth'), {
    openPrompt: async (id) => (await chrome.windows.create({ url: chrome.runtime.getURL(`${APP_PAGE}?view=window&path=${encodeURIComponent(`/http-auth/${id}`)}`), type: 'popup', width: 400, height: 520 }))?.id,
    closePrompt: (windowId) => chrome.windows.remove(windowId),
    busy: (waiting) => {
      clearInterval(promptKeepalive);
      promptKeepalive = waiting ? setInterval(() => void chrome.runtime.getPlatformInfo(), KEEPALIVE_MS) : undefined;
    },
  });
  const fillAuth = new AutofillAuth({
    canConfirmWithDevice: async () => ((await host.pageCall('deviceUnlockStatus', [])) as { enabled: boolean }).enabled,
    stayUnlocked: () => autoLock.stayUnlocked,
    openPrompt: async (id) =>
      (await chrome.windows.create({ url: chrome.runtime.getURL(`${APP_PAGE}?view=window&path=${encodeURIComponent(`/auth/fill/${id}`)}`), type: 'popup', width: 400, height: 520 }))?.id,
    closePrompt: (windowId) => chrome.windows.remove(windowId),
    busy: (waiting) => {
      clearInterval(fillKeepalive);
      fillKeepalive = waiting ? setInterval(() => void chrome.runtime.getPlatformInfo(), KEEPALIVE_MS) : undefined;
    },
  });
  const touch = () => void autoLock.touch();
  host.onActivity(touch);
  host.onEvent((event) => {
    if (event.type === 'session' && event.snapshot.session.status !== 'unlocked') {
      void autoLock.stop();
      httpAuth.cancelAll();
      fillAuth.cancelAll();
    }
    if (event.type === 'session' && event.snapshot.session.status === 'unlocked') touch();
    if (event.type === 'session') keepAwake(host.local && host.unlocked);
    if (event.type === 'session' || event.type === 'items') void refreshMatchOptions();
    for (const port of uiPorts) void postEvent(port, event);
  });
  // The user's equivalent domains, from their hidden item, for autofill matching.
  async function refreshMatchOptions(): Promise<void> {
    if (!host.unlocked) return matcher.useOptions(undefined);
    const list = await host.engine.call('equivalentDomains', []).catch(() => undefined);
    if (list) matcher.useOptions({ equivalentDomains: list.groups, excludedDefaults: list.excludedDefaults });
  }
  const sessionOptions = { keeper: host.keeper, loadCore, disk };
  const passkeys = new PasskeyRequests(new PasskeyAuthenticator({ ...sessionOptions, host, matcher }));
  const masked = new MaskedEmailFiller(host, matcher);
  const never = new NeverSave(await openKeyValueStore('octapass-never-save'), matcher);
  // Saving while locked (plan 03): sealed into an inbox in this browser, merged at the next unlock.
  const inbox = new SaveInbox(host, await openKeyValueStore('octapass-inbox'), loadFull, matcher);
  const saver = new LoginSaver(host, matcher, Date.now, masked, never, inbox);
  const icons = new SiteIcons({ serverUrl: () => host.snapshot.session.serverUrl, defaultServer: DEFAULT_SERVER_URL, enabled: siteIconsEnabled });
  const websites = new WebsiteAdder(host, matcher);
  const details = new DetailsSaver(host, matcher, never, Date.now, inbox);
  const apiKeys = new ApiKeySaver(host, matcher, never, undefined, Date.now, inbox);
  // Every unlock pins the vault's own public keys for the inbox, then merges what waits in it.
  // Equivalent domains first, so the merge matches logins as autofill does.
  const mergeInbox = () => void refreshMatchOptions().then(() => inbox.unlocked()).catch(() => undefined);
  // Which vault is open, if any: a new one (an unlock, a sign-in, Turn on sync) pins and merges.
  const opened = () => (host.unlocked ? `${host.local}|${host.snapshot.session.serverUrl}|${host.snapshot.session.email}` : undefined);
  let wasOpen = opened();
  host.onEvent((event) => {
    if (event.type !== 'session') return;
    const now = opened();
    if (now && now !== wasOpen) mergeInbox();
    wasOpen = now;
  });
  if (wasOpen) mergeInbox();
  // Plan 18: at browser start, open through the desktop app when it stays unlocked. On its own,
  // the vault is simply kept until the browser closes (the session wrap).
  if (autoLock.stayUnlocked && !host.unlocked) void host.unlockStayUnlocked(desktop).catch(() => false);
  return { host, passkeys, touch, matcher, frames, httpAuth, fillAuth, rules: await loadFull(), masked, never, saver, details, apiKeys, icons, websites };
})();

const uiPorts = new Set<chrome.runtime.Port>();
const pendingScans = new PendingScans();
const readQr: QrReader = (bytes) => coreModule.readQrImage(bytes);

const appTabs = chromeAppTabApis();
const openAppTab = (options?: OpenAppOptions) => openApp(appTabs, options);

// The toolbar button: the app page in a tab, next to the page the user is on.
chrome.action.onClicked.addListener((tab) => void openAppTab(tab.id !== undefined ? { from: tab.id } : {}));

/**
 * The popup's Fill button: the login goes to the tab's top frame, if it's for that page. With
 * `otherPart`, a login from "Logins for other parts of …": only if it's for another part of the page's
 * site, and then with the offer to add the page's website to it (null when there's none).
 */
async function fillTab(tabId: number, itemId: string): Promise<boolean>;
async function fillTab(tabId: number, itemId: string, otherPart: true): Promise<{ offer: WebsitePrompt | null } | false>;
async function fillTab(tabId: number, itemId: string, otherPart = false): Promise<boolean | { offer: WebsitePrompt | null }> {
  const { host, touch, matcher, fillAuth, websites } = await ready;
  const tab = await chrome.tabs.get(tabId);
  const item = await host.getItem(itemId);
  const values = tab.url ? (otherPart ? otherLoginFillValues : loginFillValues)(matcher, item, tab.url) : null;
  if (!values) return false;
  if (!(await fillAuth.request())) return false;
  touch();
  await chrome.tabs.sendMessage(tabId, { type: 'fill', values, origin: new URL(tab.url!).origin } satisfies FillMessage, { frameId: 0 });
  host.usage.record(itemId);
  return otherPart ? { offer: await websites.offer(item, tab.url!, tabId).catch(() => null) } : true;
}

/**
 * Plan 18 for the extension: always available (with the desktop app it opens through it, on its own
 * it keeps the vault in memory until the browser closes), so `enrolled` is the switch itself.
 */
async function stayUnlockedStatus(): Promise<StayUnlockedStatus> {
  const on = readLockSettings((await chrome.storage.local.get(LOCK_SETTINGS_KEY))[LOCK_SETTINGS_KEY] as Partial<LockSettings> | undefined).stayUnlocked;
  return { on, available: true, enrolled: on, passwordRequired: false, browser: true };
}

function uiHandlers(sender: chrome.runtime.MessageSender, context: Awaited<typeof ready>): Handlers {
  const { host, passkeys, matcher, frames, never, httpAuth } = context;
  const tabId = sender.tab?.id;
  const engine = Object.fromEntries(PAGE_METHODS.map((method) => [method, (...args: unknown[]) => host.pageCall(method, args)]));
  return {
    ...engine,
    siteItems: async (url: string) => matcher.logins(await host.listItems(), url),
    siteOtherLogins: async (url: string) => matcher.otherLogins(await host.listItems(), url),
    createLocalVault: (password: string) => host.createLocal(password),
    restoreLocalBackup: (file: Uint8Array, secret: BackupSecret, password: string) => host.restoreLocal(file, secret, password),
    localBackup: () => host.localVault.backup(),
    localInfo: async () => ({ ...(await host.localVault.meta()) }),
    localRecoveryCode: () => host.localVault.recoveryCode(),
    desktopStatus: () => desktop.status(),
    unlockWithDesktop: () => host.unlockWithDesktop(desktop),
    stayUnlockedStatus: () => stayUnlockedStatus(),
    setStayUnlocked: async (on: boolean) => {
      const current = readLockSettings((await chrome.storage.local.get(LOCK_SETTINGS_KEY))[LOCK_SETTINGS_KEY] as Partial<LockSettings> | undefined);
      await chrome.storage.local.set({ [LOCK_SETTINGS_KEY]: { ...current, stayUnlocked: on } });
      await autoLock.configure({ ...current, stayUnlocked: on });
      return stayUnlockedStatus();
    },
    unlockStayUnlocked: () => (autoLock.stayUnlocked ? host.unlockStayUnlocked(desktop) : Promise.resolve(false)),
    frameApprovals: () => frames.list(),
    removeFrameApproval: (site: string, origin: string) => frames.remove(site, origin),
    httpAuthPrompt: (id: string) => httpAuth.prompt(id),
    httpAuthApprove: (id: string, itemId: string) => httpAuth.approve(id, itemId),
    httpAuthDecline: (id: string) => httpAuth.decline(id),
    httpAuthApprovals: () => httpAuth.approvals(),
    removeHttpAuthApproval: (origin: string) => httpAuth.remove(origin),
    neverSaveSites: () => never.list(),
    removeNeverSave: (site: string, kind: SaveKind) => never.remove(site, kind),
    fillTab: (tab: number, itemId: string) => fillTab(tab, itemId),
    fillOtherLogin: (tab: number, itemId: string) => fillTab(tab, itemId, true),
    answerWebsite: (tab: number, id: string, answer: WebsiteAnswer) => context.websites.answer(id, answer, tab),
    recordItemUse: (itemId: string) => host.usage.record(itemId),
    approveFillAuth: (id: string, approved: boolean) => context.fillAuth.answer(id, approved),
    scanTab: async (tab: number) => {
      await loadFull();
      return scanTab(chrome.tabs, readQr, tab);
    },
    hasImageScan: async () => pendingScans.has(),
    takeImageScan: () => pendingScans.take(),
    passkeyPrompt: (id: string) => passkeys.prompt(id, tabId),
    passkeyMatches: (id: string) => passkeys.matches(id, tabId),
    passkeyApprove: (id: string, choice?: { itemId: string; credentialId: string }) => passkeys.approve(id, tabId, choice),
    passkeyFallback: (id: string) => passkeys.fallback(id, tabId),
    passkeyCancel: (id: string) => passkeys.cancel(id, tabId),
  };
}

chrome.runtime.onConnect.addListener((port) => {
  if (port.name === UI_PORT && port.sender && isExtensionPage(port.sender)) {
    const sender = port.sender;
    serveRpc(port, ready.then((context) => uiHandlers(sender, context)));
    void ready.then((context) => {
      uiPorts.add(port);
      port.onDisconnect.addListener(() => uiPorts.delete(port));
      void postEvent(port, { type: 'session', snapshot: context.host.snapshot });
    });
    return;
  }
  const page = port.sender && pageSender(port.sender);
  if (port.name === PASSKEY_PORT && page) {
    port.onMessage.addListener((raw: unknown) => {
      void ready.then(({ passkeys, host }) => {
        const send = (message: PasskeyPortMessage) => {
          try {
            port.postMessage(message);
          } catch {
            // The page went away.
          }
        };
        const call = parseCall(raw);
        if (!call) return send({ type: 'done', result: { kind: 'error', name: 'TypeError', message: 'Invalid passkey options.' } });
        // Cross-origin frames would need the user's per-origin approval, which isn't built yet, and passkeys need
        // an account, not a vault on this device only: the browser answers those.
        if ((page.frameId !== 0 && page.topOrigin !== page.origin) || host.local) return send({ type: 'done', result: { kind: 'fallback' } });
        const caller = { origin: page.origin, ...(page.frameId !== 0 && page.topOrigin ? { topOrigin: page.topOrigin } : {}) };
        const id = passkeys.open(call, caller, page.tabId, (result) => send({ type: 'done', result }));
        port.onDisconnect.addListener(() => passkeys.drop(id));
        send({ type: 'pending', requestId: id });
      });
    });
    return;
  }
  port.disconnect();
});

chrome.runtime.onMessage.addListener((message: ContentRequest, sender, sendResponse) => {
  const page = pageSender(sender);
  if (!page) return false;
  // Only the language preference, not the vault's storage, so pages never need to read it.
  if (message.type === 'language') {
    chrome.storage.local.get(LANGUAGE_KEY).then((stored) => sendResponse(stored[LANGUAGE_KEY] ?? 'system'), () => sendResponse('system'));
    return true;
  }
  void ready
    .then(({ host, touch, saver, details, apiKeys, matcher, frames, rules, masked, icons, fillAuth, websites }) =>
      handleContent({ host, touch, saver, details, apiKeys, matcher, frames, rules, masked, icons, fillAuth, websites, openApp: (tabId) => openAppTab({ from: tabId, back: true }) }, message, page),
    )
    .then(sendResponse, () => sendResponse(null));
  return true;
});

// "Add one-time code from QR" on images. The app tab opens at once, while the click still counts as
// the user's (Firefox requires that), and picks up the codes when they're read.
const QR_MENU = 'octapass-qr-image';
async function createQrMenu(): Promise<void> {
  const stored = (await chrome.storage.local.get(LANGUAGE_KEY))[LANGUAGE_KEY] as LanguagePreference | undefined;
  setLocale(resolveLocale(stored ?? 'system'));
  // Optional: a browser without context menus still scans from the app page.
  if (!chrome.contextMenus) return;
  await chrome.contextMenus.removeAll();
  chrome.contextMenus.create({ id: QR_MENU, title: tx('qr.menu'), contexts: ['image'] });
}
chrome.runtime.onInstalled.addListener(() => void createQrMenu());
chrome.runtime.onStartup?.addListener(() => void createQrMenu());
chrome.contextMenus?.onClicked.addListener((info, tab) => {
  if (info.menuItemId !== QR_MENU) return;
  pendingScans.start(loadFull().then(() => scanImage(chrome.tabs, readQr, info.srcUrl, tab?.id)));
  void openAppTab({ ...(tab?.id !== undefined ? { from: tab.id } : {}), path: '/scan' });
});

chrome.alarms.onAlarm.addListener((alarm) => void ready.then(() => autoLock.onAlarm(alarm.name)));
chrome.idle.onStateChanged.addListener((state) => void ready.then(() => autoLock.onIdleState(state)));

// HTTP Basic and Digest sign-in prompts. Safari has no `onAuthRequired`, so its own dialog shows there.
async function answerAuth(details: AuthChallenge & { tabId?: number }): Promise<AuthAnswer> {
  try {
    const tab = details.type !== 'main_frame' && details.tabId !== undefined && details.tabId >= 0 ? await chrome.tabs.get(details.tabId) : undefined;
    const { httpAuth } = await ready;
    return await httpAuth.answer({ ...details, ...(tab?.url ? { topOrigin: tab.url } : {}) });
  } catch {
    return {};
  }
}
const authFilter = { urls: ['http://*/*', 'https://*/*'] };
if (chrome.webRequest?.onAuthRequired) {
  if (chrome.runtime.getURL('').startsWith('moz-extension:')) {
    // Firefox waits on a returned promise.
    (chrome.webRequest.onAuthRequired.addListener as unknown as (listener: (details: AuthChallenge) => Promise<AuthAnswer>, filter: object, spec: string[]) => void)(answerAuth, authFilter, ['blocking']);
  } else {
    chrome.webRequest.onAuthRequired.addListener((details, callback) => void answerAuth(details).then((answer) => callback?.(answer)), authFilter, ['asyncBlocking']);
  }
}
chrome.windows?.onRemoved.addListener((windowId) => void ready.then(({ httpAuth, fillAuth }) => { httpAuth.windowClosed(windowId); fillAuth.windowClosed(windowId); }));
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && changes[LOCK_SETTINGS_KEY]) void autoLock.configure(changes[LOCK_SETTINGS_KEY].newValue as Partial<LockSettings>);
  if (area === 'local' && changes[LANGUAGE_KEY]) void createQrMenu();
});
