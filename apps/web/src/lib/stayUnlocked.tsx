// Plan 18: "Stay unlocked while you're logged in to this device", where the host offers it (the
// desktop app and the browser extension; never the web vault, which can't tell who's at the
// keyboard). The switch and the key live on the host's side (`VaultService.getStayUnlocked`); this
// keeps the status the screens need and runs the desktop app's migration once.

import { staysUnlocked, type StayUnlockedStatus } from '@octapass/vault-client';
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import { useService, useSession } from '../app/ServiceContext';
import { stayUnlockedByDefault } from '../app/settings';

interface StayUnlockedValue {
  /** Undefined where the host doesn't offer it, and while it loads. */
  status?: StayUnlockedStatus;
  /** On and in force on this device: no lock timer, no prompt to open or fill. */
  active: boolean;
  set: (on: boolean) => Promise<void>;
}

const StayUnlockedContext = createContext<StayUnlockedValue>({ active: false, set: async () => undefined });

export function StayUnlockedProvider({ children }: { children: ReactNode }) {
  const service = useService();
  const session = useSession();
  const [status, setStatus] = useState<StayUnlockedStatus>();

  // Again after every change of session: an unlock gives the account its key, a lock may not.
  useEffect(() => {
    if (!service.getStayUnlocked) return;
    let live = true;
    void (async () => {
      let next = await service.getStayUnlocked!();
      // Not decided on this device yet (the desktop app's first start with plan 18): new installs
      // stay unlocked, installs that already kept lock settings keep their lock (plan 18 History).
      if (next.on === null && service.setStayUnlocked) next = await service.setStayUnlocked(stayUnlockedByDefault());
      if (live) setStatus(next);
    })().catch(() => undefined);
    return () => {
      live = false;
    };
  }, [service, session.status, session.email, session.serverUrl]);

  const set = useCallback(
    async (on: boolean) => {
      if (!service.setStayUnlocked) return;
      setStatus(await service.setStayUnlocked(on));
    },
    [service],
  );
  const value = useMemo(() => ({ status, active: staysUnlocked(status), set }), [status, set]);
  return <StayUnlockedContext.Provider value={value}>{children}</StayUnlockedContext.Provider>;
}

export function useStayUnlocked(): StayUnlockedValue {
  return useContext(StayUnlockedContext);
}
