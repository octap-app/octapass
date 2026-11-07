// Browser profiles for the server-backed tests: each has its own storage, engine and page-side
// service, on the Node build of the WASM core.

import { createRequire } from 'node:module';
import { openKeyValueStore } from '../../idb';
import { isVaultError, type VaultError } from '../../errors';
import { VaultEngine, type Core, type EngineOptions } from '../engine';
import { directClient, type EngineClient } from '../protocol';
import { RemoteVaultService } from '../RemoteVaultService';

export const core = createRequire(import.meta.url)('@octapass/core/node') as Core;
export const PASSWORD = 'Lantern ruby quiet anchor 42';

export interface TestDevice {
  service: RemoteVaultService;
  engine: EngineClient;
  storage: string;
}

export interface SignedUpDevice extends TestDevice {
  email: string;
  secretKey: string;
  /** Only from `signedUp`, which saw the Recovery Kit. */
  recoveryCode?: string;
}

let devices = 0;
let emails = 0;

/** A browser profile. Polling is off, so only explicit syncs and live notifications bring changes. */
export async function device(storage = `device-${devices++}`, options: Partial<EngineOptions> = {}): Promise<TestDevice> {
  const kv = await openKeyValueStore(storage);
  const engine = directClient((emit) => new VaultEngine({ loadCore: async () => core, storage: kv, emit, ...options }));
  const service = await RemoteVaultService.create(engine, { watch: () => () => undefined });
  return { service, engine, storage };
}

export async function signedUp(serverUrl: string, options: Partial<EngineOptions> = {}): Promise<SignedUpDevice> {
  const d = await device(undefined, options);
  const email = `user${emails++}-${Date.now()}@example.com`;
  const { signupId, devVerificationCode } = await d.service.startSignup({ serverUrl, email, password: PASSWORD });
  const { recoveryKit } = await d.service.finishSignup({ signupId, verificationCode: devVerificationCode! });
  return { ...d, email, secretKey: recoveryKit.secretKey, recoveryCode: recoveryKit.recoveryCode };
}

export async function expectCode(promise: Promise<unknown>, code: VaultError['code']): Promise<void> {
  const error = await promise.then(
    () => undefined,
    (e: unknown) => e,
  );
  expect(isVaultError(error) ? error.code : error).toBe(code);
}

/** Retries `check` until it stops throwing: for what arrives over the WebSocket. */
export async function eventually<T>(check: () => Promise<T> | T, timeoutMs = 10_000): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      return await check();
    } catch (error) {
      if (Date.now() > deadline) throw error;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
  }
}
