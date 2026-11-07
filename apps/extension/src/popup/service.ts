// The extension pages' side of the vault: the web vault's RemoteVaultService over a port to the
// service worker, plus the calls only the extension has.

import type { PasskeyMatch } from '@octapass/core';
import type { BackupSecret } from '@octapass/core/full';
import type { ItemSummary, QrCaptureService, StayUnlockedStatus, VaultService } from '@octapass/vault-client';
import { RemoteVaultService, type EngineClient } from '@octapass/vault-client/remote';
import type { DesktopStatus } from '../background/desktop';
import type { FrameApproval } from '../background/frames';
import type { HttpAuthApproval, HttpAuthPrompt } from '../background/httpAuth';
import type { OtherPartLogin } from '../background/matching';
import type { NeverSaveEntry, SaveKind } from '../background/neverSave';
import type { LocalMeta } from '../shared/local';
import type { WebsiteAnswer, WebsitePrompt } from '../shared/messages';
import type { PasskeyPrompt } from '../shared/passkey';
import { rpcClient, UI_PORT, type RpcClient } from '../shared/rpc';

export interface ExtensionApi {
  /** Logins for a page, best match first. */
  siteItems(url: string): Promise<ItemSummary[]>;
  /** Logins for other parts of the page's site, by host: listed apart, filled only when picked. */
  siteOtherLogins(url: string): Promise<OtherPartLogin[]>;
  /** Fills a login into a tab's page; false when the login isn't for that page. */
  fillTab(tabId: number, itemId: string): Promise<boolean>;
  /**
   * Fills a login from "Logins for other parts of …" into a tab's page; false when it isn't for
   * another part of that page's site. `offer`: may Octa Pass add the page's website to it?
   */
  fillOtherLogin(tabId: number, itemId: string): Promise<{ offer: WebsitePrompt | null } | false>;
  /** The answer to that offer; true once the login has the website. */
  answerWebsite(tabId: number, id: string, answer: WebsiteAnswer): Promise<boolean>;
  /** Copying from an item counts as using it (filling counts by itself). */
  recordItemUse(itemId: string): Promise<void>;
  /** The autofill prompt window's answer: true fills, false cancels. */
  approveFillAuth(id: string, approved: boolean): Promise<void>;
  /** The QR codes in what the tab shows, read in the service worker. */
  scanTab(tabId: number): Promise<string[]>;
  /** The image menu's "Add one-time code from QR" left codes for the popup. */
  hasImageScan(): Promise<boolean>;
  /** Those codes, once. */
  takeImageScan(): Promise<string[] | undefined>;
  passkeyPrompt(requestId: string): Promise<PasskeyPrompt>;
  passkeyMatches(requestId: string): Promise<PasskeyMatch[]>;
  passkeyApprove(requestId: string, choice?: Pick<PasskeyMatch, 'itemId' | 'credentialId'>): Promise<void>;
  passkeyFallback(requestId: string): Promise<void>;
  passkeyCancel(requestId: string): Promise<void>;
  /** "Use on this device only": returns the backup recovery code. */
  createLocalVault(password: string): Promise<string>;
  restoreLocalBackup(file: Uint8Array, secret: BackupSecret, password: string): Promise<void>;
  localBackup(): Promise<Blob>;
  localInfo(): Promise<Partial<LocalMeta>>;
  localRecoveryCode(): Promise<string>;
  /** The desktop app, over native messaging. */
  desktopStatus(): Promise<DesktopStatus>;
  unlockWithDesktop(): Promise<void>;
  /** Plan 18: "Stay unlocked while you're logged in to this device". */
  stayUnlockedStatus(): Promise<StayUnlockedStatus>;
  setStayUnlocked(on: boolean): Promise<StayUnlockedStatus>;
  /** Opens through the desktop app with no prompt, when it stays unlocked; false otherwise. */
  unlockStayUnlocked(): Promise<boolean>;
  /** Frames from other sites the user let Octa Pass fill. */
  frameApprovals(): Promise<FrameApproval[]>;
  removeFrameApproval(site: string, origin: string): Promise<void>;
  /** An HTTP sign-in prompt waiting for the user, by the id in the prompt window's path. */
  httpAuthPrompt(id: string): Promise<HttpAuthPrompt>;
  httpAuthApprove(id: string, itemId: string): Promise<void>;
  httpAuthDecline(id: string): Promise<void>;
  /** Sites whose HTTP sign-in prompts Octa Pass answers. */
  httpAuthApprovals(): Promise<HttpAuthApproval[]>;
  removeHttpAuthApproval(origin: string): Promise<void>;
  /** Sites where the user answered "Never" to a save prompt. */
  neverSaveSites(): Promise<NeverSaveEntry[]>;
  removeNeverSave(site: string, kind: SaveKind): Promise<void>;
}

function engineClient(rpc: RpcClient): EngineClient {
  return {
    call: (method, args) => rpc.call(method, args) as never,
    onEvent: (listener) => void rpc.onEvent((event) => listener(event as never)),
  };
}

function extensionApi(rpc: RpcClient): ExtensionApi {
  const call =
    <K extends keyof ExtensionApi>(method: K) =>
    (...args: Parameters<ExtensionApi[K]>) =>
      rpc.call(method, args) as ReturnType<ExtensionApi[K]>;
  return {
    siteItems: call('siteItems'),
    siteOtherLogins: call('siteOtherLogins'),
    fillTab: call('fillTab'),
    fillOtherLogin: call('fillOtherLogin'),
    answerWebsite: call('answerWebsite'),
    recordItemUse: call('recordItemUse'),
    approveFillAuth: call('approveFillAuth'),
    scanTab: call('scanTab'),
    hasImageScan: call('hasImageScan'),
    takeImageScan: call('takeImageScan'),
    passkeyPrompt: call('passkeyPrompt'),
    passkeyMatches: call('passkeyMatches'),
    passkeyApprove: call('passkeyApprove'),
    passkeyFallback: call('passkeyFallback'),
    passkeyCancel: call('passkeyCancel'),
    createLocalVault: call('createLocalVault'),
    restoreLocalBackup: call('restoreLocalBackup'),
    localBackup: call('localBackup'),
    localInfo: call('localInfo'),
    localRecoveryCode: call('localRecoveryCode'),
    desktopStatus: call('desktopStatus'),
    unlockWithDesktop: call('unlockWithDesktop'),
    stayUnlockedStatus: call('stayUnlockedStatus'),
    setStayUnlocked: call('setStayUnlocked'),
    unlockStayUnlocked: call('unlockStayUnlocked'),
    frameApprovals: call('frameApprovals'),
    removeFrameApproval: call('removeFrameApproval'),
    httpAuthPrompt: call('httpAuthPrompt'),
    httpAuthApprove: call('httpAuthApprove'),
    httpAuthDecline: call('httpAuthDecline'),
    httpAuthApprovals: call('httpAuthApprovals'),
    removeHttpAuthApproval: call('removeHttpAuthApproval'),
    neverSaveSites: call('neverSaveSites'),
    removeNeverSave: call('removeNeverSave'),
  };
}

/**
 * `scanPage`: reads the QR codes on the page the user was on, for "Scan QR code on this page" (the
 * app tab has one; the prompt windows don't).
 */
export async function connectVault({ scanPage }: { scanPage?: (api: ExtensionApi) => Promise<string[]> } = {}): Promise<{ service: RemoteVaultService; api: ExtensionApi }> {
  const rpc = rpcClient(() => chrome.runtime.connect({ name: UI_PORT }));
  const api = extensionApi(rpc);
  const qrCapture: QrCaptureService | undefined = scanPage && {
    sources: ['page'],
    chooseFiles: true,
    capture: () => scanPage(api),
  };
  // Extension pages may call any site the extension has host access to, so every masked email provider works here.
  // SSH private keys stay out of the extension: its pages show public keys and fingerprints only.
  const service = await RemoteVaultService.create(engineClient(rpc), { maskedEmail: { context: 'extension' }, sshKeys: false, toolkitFiles: false, ...(qrCapture ? { qrCapture } : {}) });
  // Plan 18's switch lives with the service worker's lock settings.
  Object.assign(service, {
    getStayUnlocked: () => api.stayUnlockedStatus(),
    setStayUnlocked: (on: boolean) => api.setStayUnlocked(on),
    unlockStayUnlocked: () => api.unlockStayUnlocked(),
  } satisfies Pick<VaultService, 'getStayUnlocked' | 'setStayUnlocked' | 'unlockStayUnlocked'>);
  return { service, api };
}
