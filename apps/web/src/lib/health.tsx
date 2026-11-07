import { createHealthSettings, emailBreachAddresses, withoutWarnings, type EmailBreachCheck, type HealthReport, type HealthSettings } from '@octapass/vault-client';
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { useService, useSession } from '../app/ServiceContext';

interface HealthState {
  report: HealthReport | undefined;
  loading: boolean;
  error: unknown;
  refresh: () => void;
  settings: HealthSettings;
  /** Hides warnings at once, then saves them in the vault. Rejects, and shows them again, if that fails. */
  dismiss: (warnings: string[]) => Promise<void>;
  restore: (warnings: string[]) => Promise<void>;
  /** What the last email breach check did. */
  emailCheck: EmailBreachCheck | undefined;
  /** Sends the addresses when alerts are on and a check is due, or `force`. */
  checkEmails: (force?: boolean) => Promise<void>;
}

const HealthContext = createContext<HealthState | null>(null);

/** Shares one health report between the sidebar ring and the Health page, and refreshes it after edits. */
export function HealthProvider({ children }: { children: ReactNode }) {
  const service = useService();
  const { email } = useSession();
  const settings = useMemo(() => createHealthSettings(service), [service]);
  const [report, setReport] = useState<HealthReport>();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>();
  const [hidden, setHidden] = useState<ReadonlySet<string>>(new Set());
  const [emailCheck, setEmailCheck] = useState<EmailBreachCheck>();
  const run = useRef(0);
  const asked = useRef(false);

  const refresh = useCallback(() => {
    const current = ++run.current;
    setLoading(true);
    service.getHealthReport().then(
      (next) => {
        if (current !== run.current) return;
        setReport(next);
        setHidden(new Set());
        setError(undefined);
        setLoading(false);
      },
      (e: unknown) => {
        if (current !== run.current) return;
        setError(e);
        setLoading(false);
      },
    );
  }, [service]);

  useEffect(() => {
    refresh();
    let timer: ReturnType<typeof setTimeout>;
    const unsubscribe = service.onItemsChange(() => {
      clearTimeout(timer);
      timer = setTimeout(refresh, 600);
    });
    return () => {
      clearTimeout(timer);
      unsubscribe();
      run.current++;
    };
  }, [service, refresh]);

  const checkEmails = useCallback(
    async (force = false) => {
      if (!report) return;
      asked.current = true;
      const result = await settings.checkEmailBreaches(emailBreachAddresses(email, report), { force });
      setEmailCheck(result);
    },
    [settings, email, report],
  );

  // Once per unlock: `checkEmailBreaches` sends nothing unless alerts are on and a day has passed.
  useEffect(() => {
    if (!report?.emailBreaches.enabled || asked.current) return;
    void checkEmails();
  }, [report, checkEmails]);

  const dismiss = useCallback(
    async (warnings: string[]) => {
      setHidden((current) => new Set([...current, ...warnings]));
      try {
        await settings.dismiss(warnings);
      } catch (e) {
        setHidden((current) => new Set([...current].filter((key) => !warnings.includes(key))));
        throw e;
      }
    },
    [settings],
  );

  const restore = useCallback(
    async (warnings: string[]) => {
      await settings.restore(warnings);
      refresh();
    },
    [settings, refresh],
  );

  const visible = useMemo(() => (report && hidden.size > 0 ? withoutWarnings(report, hidden) : report), [report, hidden]);

  const value = useMemo(
    () => ({ report: visible, loading, error, refresh, settings, dismiss, restore, emailCheck, checkEmails }),
    [visible, loading, error, refresh, settings, dismiss, restore, emailCheck, checkEmails],
  );
  return <HealthContext.Provider value={value}>{children}</HealthContext.Provider>;
}

export function useHealth(): HealthState {
  const value = useContext(HealthContext);
  if (!value) throw new Error('useHealth must be used inside <HealthProvider>');
  return value;
}

/** The report where a Health page exists (not in the extension popup), or undefined. */
export function useHealthReport(): HealthReport | undefined {
  return useContext(HealthContext)?.report;
}

export function scoreTone(score: number): 'free' | 'warn' | 'danger' {
  return score >= 80 ? 'free' : score >= 50 ? 'warn' : 'danger';
}
