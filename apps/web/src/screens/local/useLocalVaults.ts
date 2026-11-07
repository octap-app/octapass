import type { LocalVaultInfo } from '@octapass/vault-client';
import { useCallback, useEffect, useState } from 'react';
import { useService, useSession } from '../../app/ServiceContext';

/** Every vault on this device, loaded again when the session changes. Empty without `service.local`. */
export function useLocalVaults(): { vaults: LocalVaultInfo[]; current: LocalVaultInfo | undefined; reload: () => void } {
  const service = useService();
  const session = useSession();
  const [vaults, setVaults] = useState<LocalVaultInfo[]>([]);
  const reload = useCallback(() => {
    void service.local?.list().then(setVaults);
  }, [service]);
  useEffect(reload, [reload, session.status, session.email]);
  return { vaults, current: vaults.find((vault) => vault.current), reload };
}

const DAY_MS = 86_400_000;

/** Whole days since an ISO time. */
export function daysSince(iso: string, now = Date.now()): number {
  return Math.floor((now - new Date(iso).getTime()) / DAY_MS);
}

export function backupFilename(now = new Date()): string {
  return `octapass-${now.toISOString().slice(0, 10)}.octapass-backup`;
}
