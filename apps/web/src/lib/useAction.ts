import { useToast } from '@octapass/ui';
import { useCallback, useState } from 'react';
import { errorMessage } from './errors';

/**
 * Runs one action at a time, with a toast for the outcome. `busy` names the running action, so a
 * list of rows can show which one is working.
 */
export function useAction(): { busy: string | undefined; run: (key: string, action: () => Promise<unknown>, success?: string) => Promise<boolean> } {
  const toast = useToast();
  const [busy, setBusy] = useState<string>();
  const run = useCallback(
    async (key: string, action: () => Promise<unknown>, success?: string) => {
      setBusy(key);
      try {
        await action();
        if (success) toast({ message: success, tone: 'success' });
        return true;
      } catch (e) {
        toast({ message: errorMessage(e), tone: 'danger' });
        return false;
      } finally {
        setBusy(undefined);
      }
    },
    [toast],
  );
  return { busy, run };
}
