import { isLocalServer, type SharingService } from '@octapass/vault-client';
import { useService, useSession } from '../app/ServiceContext';
import { useLive } from './useItems';

/** The service's sharing features, if it has them: hosts without a sync server account don't. */
export function useSharing(): SharingService | undefined {
  const service = useService();
  const session = useSession();
  // A vault on this device only has no account to share from.
  return isLocalServer(session.serverUrl) ? undefined : service.sharing;
}

/** Loads sharing data, again whenever items or sharing change. Nothing loads without sharing. */
export function useSharingData<T>(load: (sharing: SharingService) => Promise<T>, deps: unknown[] = []): { data: T | undefined; error: unknown; retry: () => void } {
  const sharing = useSharing();
  return useLive(() => (sharing ? load(sharing) : new Promise<T>(() => undefined)), [sharing, ...deps], { sharing: true });
}
