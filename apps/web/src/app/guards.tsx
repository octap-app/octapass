import type { ReactNode } from 'react';
import { Navigate, useLocation } from 'react-router';
import { useExitTo, useSession } from './ServiceContext';

/** Vault routes: signed out goes to sign-in, locked goes to the lock screen and comes back after. */
export function RequireUnlocked({ children }: { children: ReactNode }) {
  const session = useSession();
  const location = useLocation();
  const exitTo = useExitTo();
  if (session.status === 'unlocked') return children;
  if (session.status === 'locked') return <Navigate to="/lock" replace state={{ from: location.pathname + location.search }} />;
  return <Navigate to={exitTo.current ?? '/welcome'} replace />;
}

/** Sign-in screens: skip them when there's already a session. */
export function RequireSignedOut({ children }: { children: ReactNode }) {
  const session = useSession();
  if (session.status === 'unlocked') return <Navigate to="/" replace />;
  if (session.status === 'locked') return <Navigate to="/lock" replace />;
  return children;
}

export function RequireLocked({ children }: { children: ReactNode }) {
  const session = useSession();
  const location = useLocation();
  const from = (location.state as { from?: string } | null)?.from;
  if (session.status === 'unlocked') return <Navigate to={from ?? '/'} replace />;
  if (session.status === 'signedOut') return <Navigate to="/welcome" replace />;
  return children;
}
