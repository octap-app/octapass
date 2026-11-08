// The message bridge between the page and wherever the engine runs. Only this file knows about
// postMessage; the engine and the page-side service don't.

import { VaultError, type VaultErrorCode } from '../errors';
import type { EngineEvent, VaultEngine } from './engine';
import { normalizeError } from './errors';

/** The engine methods the page may call. Anything else is refused. */
export const ENGINE_METHODS = [
  'init',
  'preload',
  'getServerInfo',
  'startSignup',
  'finishSignup',
  'signIn',
  'finishTwoStep',
  'finishSso',
  'pendingTwoStep',
  'cancelTwoStep',
  'lock',
  'unlock',
  'signOut',
  'getSecretKey',
  'getAccountSummary',
  'deleteAccount',
  'changeMasterPassword',
  'rotateSecretKey',
  'startPasswordReset',
  'verifyPasswordReset',
  'finishPasswordReset',
  'cancelPasswordReset',
  'getTwoStepStatus',
  'startTotpSetup',
  'confirmTotpSetup',
  'securityKeyOptions',
  'addSecurityKey',
  'removeSecurityKey',
  'renewRecoveryCodes',
  'disableTwoStep',
  'forgetTrustedDevices',
  'deviceUnlockStatus',
  'enableDeviceUnlock',
  'disableDeviceUnlock',
  'deviceUnlockCredential',
  'unlockWithDevice',
  'listVaults',
  'listItems',
  'getItem',
  'saveItem',
  'deleteItem',
  'restoreItem',
  'itemVersions',
  'restoreItemVersion',
  'nextHotpCode',
  'setHotpCounter',
  'equivalentDomains',
  'saveEquivalentDomains',
  'generatePasswordForSite',
  'addAttachment',
  'getAttachment',
  'removeAttachment',
  'getStorageUsage',
  'sync',
  'backgroundSync',
  'listDevices',
  'renameDevice',
  'signOutDevice',
  'getMyFingerprint',
  'lookupAccount',
  'getOrganisation',
  'createOrganisation',
  'renameOrganisation',
  'deleteOrganisation',
  'acceptOrgInvite',
  'declineOrgInvite',
  'listOrgMembers',
  'inviteOrgMember',
  'cancelOrgInvite',
  'setOrgMemberRole',
  'removeOrgMember',
  'leaveOrganisation',
  'listOrgGroups',
  'createOrgGroup',
  'renameOrgGroup',
  'deleteOrgGroup',
  'addOrgGroupMember',
  'removeOrgGroupMember',
  'listOrgVaults',
  'createOrgVault',
  'deleteOrgVault',
  'linkOrgVaultGroup',
  'unlinkOrgVaultGroup',
  'getOrgAccess',
  'applyOrgAccess',
  'rotateOrgVault',
  'setOrgPolicies',
  'getOrgSso',
  'saveOrgSso',
  'saveOrgSaml',
  'removeOrgSso',
  'getOrgScim',
  'createOrgScimToken',
  'revokeOrgScimToken',
  'testOrgSso',
  'listOrgEvents',
  'markVerified',
  'getKeyLogState',
  'dismissKeyLogAlert',
  'createVault',
  'renameVault',
  'listMembers',
  'addMember',
  'changeRole',
  'removeMember',
  'leaveVault',
  'listServiceAccounts',
  'createServiceAccount',
  'revokeServiceAccount',
  'moveItem',
  'copyItem',
  'getFamily',
  'createFamily',
  'inviteToFamily',
  'acceptFamilyInvite',
  'declineFamilyInvite',
  'cancelFamilyInvite',
  'removeFamilyMember',
  'leaveFamily',
  'deleteFamily',
  'createShareLink',
  'listShareLinks',
  'revokeShareLink',
  'fetchShareLink',
  'openShareLink',
  'listEmergencyContacts',
  'addEmergencyContact',
  'removeEmergencyContact',
  'requestEmergencyAccess',
  'denyEmergencyAccess',
  'approveEmergencyAccess',
  'openEmergencyAccess',
  'getEmergencyAttachment',
  'renewEmergencyKey',
  'takeOverAccount',
  'enableOrganiserRecovery',
  'rotateVaultKey',
  'getSecurityLog',
  'totpCode',
  'checkBreached',
  'getHealthReport',
  'lookupEmailBreaches',
  'exportVault',
  'importFile',
  'reviewImport',
  'finishImport',
  'cancelImport',
  'readQrCodes',
  'summarizeQrScans',
  'generateSshKey',
  'readSshKey',
  'writeSshKey',
  'toolRun',
  'toolHashFile',
  'confirmMasterPassword',
  'confirmDeviceCredential',
  'confirmWithDevice',
  // The save inbox (plan 03, Saving while locked): the browser extension pins and opens it at unlock.
  'pinInbox',
  'openInbox',
] as const satisfies readonly (keyof VaultEngine)[];

export type EngineMethod = (typeof ENGINE_METHODS)[number];
type Fn<M extends EngineMethod> = VaultEngine[M] extends (...args: infer A) => infer R ? (...args: A) => R : never;
export type EngineArgs<M extends EngineMethod> = Parameters<Fn<M>>;
export type EngineResult<M extends EngineMethod> = Awaited<ReturnType<Fn<M>>>;

/** How the page talks to the engine, wherever it runs. */
export interface EngineClient {
  call<M extends EngineMethod>(method: M, args: EngineArgs<M>, transfer?: Transferable[]): Promise<EngineResult<M>>;
  onEvent(listener: (event: EngineEvent) => void): void;
}

interface Request {
  id: number;
  method: string;
  args: unknown[];
}

type Response = { id: number; ok: true; value: unknown } | { id: number; ok: false; error: SerializedError };
type Message = Response | { event: EngineEvent };

interface SerializedError {
  name: string;
  message: string;
  code?: VaultErrorCode;
}

function serializeError(error: unknown): SerializedError {
  const normalized = normalizeError(error);
  if (normalized instanceof VaultError) return { name: normalized.name, message: normalized.message, code: normalized.code };
  if (normalized instanceof Error) return { name: normalized.name, message: normalized.message };
  return { name: 'Error', message: String(normalized) };
}

function deserializeError(error: SerializedError): Error {
  if (error.code) return new VaultError(error.code, error.message);
  return Object.assign(new Error(error.message), { name: error.name });
}

/** The minimal port shape shared by a Worker, a worker's global scope and a MessagePort. */
export interface Port {
  postMessage(message: unknown, transfer?: Transferable[]): void;
  addEventListener(type: 'message', listener: (event: MessageEvent) => void): void;
}

/** Engine side: answers calls arriving on `port`. `engine` may still be starting up. */
export function serveEngine(engine: Promise<VaultEngine>, port: Port): void {
  const allowed = new Set<string>(ENGINE_METHODS);
  port.addEventListener('message', (event) => {
    const { id, method, args } = event.data as Request;
    void (async () => {
      try {
        if (!allowed.has(method)) throw new Error(`Unknown method ${method}`);
        const target = await engine;
        const value = await (target[method as EngineMethod] as (...a: unknown[]) => unknown).apply(target, args);
        port.postMessage({ id, ok: true, value } satisfies Response);
      } catch (error) {
        port.postMessage({ id, ok: false, error: serializeError(error) } satisfies Response);
      }
    })();
  });
}

/** Sends engine events to the page. */
export function postEvents(port: Port): (event: EngineEvent) => void {
  return (event) => port.postMessage({ event } satisfies Message);
}

/** Page side of `serveEngine`. */
export function portClient(port: Port): EngineClient {
  const pending = new Map<number, { resolve: (value: never) => void; reject: (error: Error) => void }>();
  const listeners = new Set<(event: EngineEvent) => void>();
  let nextId = 1;

  port.addEventListener('message', (event) => {
    const message = event.data as Message;
    if ('event' in message) {
      for (const listener of listeners) listener(message.event);
      return;
    }
    const call = pending.get(message.id);
    if (!call) return;
    pending.delete(message.id);
    if (message.ok) call.resolve(message.value as never);
    else call.reject(deserializeError(message.error));
  });

  return {
    call(method, args, transfer = []) {
      const id = nextId++;
      return new Promise((resolve, reject) => {
        pending.set(id, { resolve, reject });
        port.postMessage({ id, method, args } satisfies Request, transfer);
      });
    },
    onEvent: (listener) => void listeners.add(listener),
  };
}

/**
 * The engine in the same context, without a bridge: for tests, and for hosts that are already
 * isolated from page scripts. Errors are normalised the same way as across the bridge.
 */
export function directClient(create: (emit: (event: EngineEvent) => void) => VaultEngine): EngineClient {
  const listeners = new Set<(event: EngineEvent) => void>();
  const engine = create((event) => {
    for (const listener of listeners) listener(structuredClone(event));
  });
  return {
    async call(method, args) {
      try {
        return (await (engine[method] as (...a: unknown[]) => unknown).apply(engine, args)) as never;
      } catch (error) {
        throw deserializeError(serializeError(error));
      }
    },
    onEvent: (listener) => void listeners.add(listener),
  };
}
