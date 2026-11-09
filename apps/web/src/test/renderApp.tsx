import { createRequire } from 'node:module';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { PlacesCore, SshCore, VaultService } from '@octapass/vault-client';
import { DEFAULT_SERVER_URL, MockVaultService } from '@octapass/vault-client/mock';
import { App } from '../app/App';
import { createTestRouter } from '../app/routes';

let db = 0;
export const PASSWORD = 'Lantern ruby quiet anchor 42';
export const EMAIL = 'maya@example.com';

/** The real core's SSH key and Nearby functions (Node build). */
const sshCore = createRequire(import.meta.url)('@octapass/core/node') as SshCore;

export function createService(): Promise<MockVaultService> {
  return MockVaultService.create({ dbName: `web-test-${db++}`, latency: [0, 0], fetch: async () => new Response(''), sshCore: async () => sshCore, placesCore: async () => sshCore as unknown as PlacesCore });
}

/** A service with a signed-up, unlocked demo account. */
export async function createSignedInService(): Promise<MockVaultService> {
  const service = await createService();
  const { signupId, devVerificationCode } = await service.startSignup({ serverUrl: DEFAULT_SERVER_URL, email: EMAIL, password: PASSWORD });
  await service.finishSignup({ signupId, verificationCode: devVerificationCode! });
  return service;
}

export function renderApp(service: VaultService, path = '/') {
  const router = createTestRouter(path);
  const user = userEvent.setup();
  const { unmount } = render(<App service={service} router={router} />);
  return { router, user, screen, unmount };
}
