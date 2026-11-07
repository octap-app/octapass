import type { SessionState, VaultService } from '@octapass/vault-client';
import { createContext, useCallback, useContext, useRef, useSyncExternalStore, type ReactNode, type RefObject } from 'react';

interface ServiceContextValue {
  service: VaultService;
  /**
   * Where to go when the session ends on purpose (for example after deleting the account), so the
   * route guards don't bounce to the sign-in screen first.
   */
  exitTo: RefObject<string | null>;
}

const ServiceContext = createContext<ServiceContextValue | null>(null);

export function ServiceProvider({ service, children }: { service: VaultService; children: ReactNode }) {
  const exitTo = useRef<string | null>(null);
  return <ServiceContext.Provider value={{ service, exitTo }}>{children}</ServiceContext.Provider>;
}

function useServiceContext(): ServiceContextValue {
  const value = useContext(ServiceContext);
  if (!value) throw new Error('useService must be used inside <ServiceProvider>');
  return value;
}

export function useService(): VaultService {
  return useServiceContext().service;
}

export function useExitTo(): RefObject<string | null> {
  return useServiceContext().exitTo;
}

export function useSession(): SessionState {
  const service = useService();
  const subscribe = useCallback((cb: () => void) => service.onSessionChange(cb), [service]);
  return useSyncExternalStore(subscribe, () => service.getSession());
}
