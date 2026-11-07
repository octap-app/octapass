import type { VaultService } from '@octapass/vault-client';
import type { ExtensionApi } from './service';

/**
 * Where the popup opens. After the image menu's "Add one-time code from QR", on the scan. The popup closes whenever the user switches away, such as to read a code
 * from an authenticator app, so a sign-in waiting for its second step (or one just lost) opens on the
 * sign-in screen, which picks it up.
 */
export async function startPath(service: VaultService, requested: string | null, api?: Pick<ExtensionApi, 'hasImageScan'>): Promise<string> {
  if (requested) return requested;
  // Opened by "Add one-time code from QR" on a page's image.
  if (api && (await api.hasImageScan().catch(() => false))) return '/scan';
  if (service.getSession().status !== 'signedOut' || !service.pendingTwoStep) return '/';
  const waiting = await service.pendingTwoStep().catch(() => undefined);
  return waiting ? '/signin' : '/';
}
