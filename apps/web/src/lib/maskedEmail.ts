import { useToast } from '@octapass/ui';
import { providerInfo, type MaskedAlias, type MaskedEmailConnection, type MaskedEmailProviderId, type MaskedEmailService } from '@octapass/vault-client';
import { useCallback, useState } from 'react';
import { useService } from '../app/ServiceContext';
import { errorMessage } from './errors';
import { useLive } from './useItems';

export function providerName(id: MaskedEmailProviderId): string {
  return providerInfo(id).name;
}

/** The connected providers, kept fresh as the vault changes. Undefined while loading or where masked email isn't wired up. */
export function useConnections(): MaskedEmailConnection[] | undefined {
  const masked = useService().maskedEmail;
  return useLive(async () => (masked ? masked.listConnections() : undefined), [masked]).data;
}

/** Runs a change to an alias, with a toast either way. */
export function useAliasChange(): { run: (change: (masked: MaskedEmailService) => Promise<void>, done: string) => Promise<void>; busy: boolean } {
  const masked = useService().maskedEmail;
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const run = useCallback(
    async (change: (masked: MaskedEmailService) => Promise<void>, done: string) => {
      if (!masked) return;
      setBusy(true);
      try {
        await change(masked);
        toast({ message: done, tone: 'success' });
      } catch (error) {
        toast({ message: errorMessage(error), tone: 'danger' });
      } finally {
        setBusy(false);
      }
    },
    [masked, toast],
  );
  return { run, busy };
}

/** Makes an alias for a site, with a toast when it fails. Resolves to undefined then. */
export function useCreateAlias(): { create: (site: string, connectionId?: string) => Promise<MaskedAlias | undefined>; busy: boolean } {
  const masked = useService().maskedEmail;
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const create = useCallback(
    async (site: string, connectionId?: string) => {
      if (!masked) return undefined;
      setBusy(true);
      try {
        return await masked.createAlias({ site, ...(connectionId ? { connectionId } : {}) });
      } catch (error) {
        toast({ message: errorMessage(error), tone: 'danger' });
        return undefined;
      } finally {
        setBusy(false);
      }
    },
    [masked, toast],
  );
  return { create, busy };
}
