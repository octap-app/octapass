import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from 'react';
import { Icon, type IconName } from './Icon';
import styles from './Toaster.module.css';

export interface ToastInput {
  message: string;
  tone?: 'neutral' | 'success' | 'danger';
  icon?: IconName;
  /** Milliseconds. */
  duration?: number;
}

interface Toast extends ToastInput {
  id: number;
}

const ToastContext = createContext<((toast: ToastInput) => void) | null>(null);

const listeners = new Set<(toast: ToastInput) => void>();

/** Hears every toast as it's shown; the phone app adds a haptic to each. Returns the unsubscribe. */
export function onToast(listener: (toast: ToastInput) => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

/**
 * Shows short confirmations ("Password copied") and speaks them through a polite live region,
 * so screen reader users hear every copy and save.
 */
export function Toaster({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [spoken, setSpoken] = useState('');
  const next = useRef(0);

  const show = useCallback((input: ToastInput) => {
    const id = ++next.current;
    setToasts((current) => [...current.slice(-2), { ...input, id }]);
    // Re-setting identical text wouldn't be announced again, so toggle a zero-width suffix.
    setSpoken(input.message + (id % 2 ? '' : '​'));
    setTimeout(() => setToasts((current) => current.filter((t) => t.id !== id)), input.duration ?? 2600);
    for (const listener of listeners) listener(input);
  }, []);

  const value = useMemo(() => show, [show]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="visually-hidden" role="status" aria-live="polite" aria-atomic="true">
        {spoken}
      </div>
      <div className={styles.stack} aria-hidden="true">
        {toasts.map((toast) => (
          <div key={toast.id} className={[styles.toast, styles[toast.tone ?? 'neutral']].join(' ')}>
            <Icon name={toast.icon ?? (toast.tone === 'danger' ? 'alert' : 'check')} size={18} />
            <span>{toast.message}</span>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast(): (toast: ToastInput) => void {
  const show = useContext(ToastContext);
  if (!show) throw new Error('useToast must be used inside <Toaster>');
  return show;
}
