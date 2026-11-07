// "Confirm it's you" before a secret is revealed, copied or exported (plan 03, the two-gate model):
// device unlock where this device has it, the master password otherwise. On a device with no lock
// the master password is the only gate left, so this never becomes gateless.
//
// Two gates (plan 03 History, 2026-11-06, maintainer decision): `useConfirmReveal` for revealing and
// copying, which doesn't ask while the vault is open, however it was opened; `useConfirmIdentity`
// for exports, the Secret Key, the Recovery Kit and the account's settings, which asks every time.

import { Button, Dialog } from '@octapass/ui';
import { isVaultError, type VaultService } from '@octapass/vault-client';
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { PasswordInput } from '../components/PasswordInput';
import { Alert } from '../components/Alert';
import { t } from '../i18n';
import { errorMessage } from './errors';
import { useService } from '../app/ServiceContext';
import styles from './identityGate.module.css';

/** Resolves true when the user confirmed, false when they closed the dialog or cancelled. */
export type ConfirmIdentity = (options?: { reason?: string }) => Promise<boolean>;

interface Request {
  resolve: (confirmed: boolean) => void;
  reason?: string;
}

const IdentityGateContext = createContext<{ confirm: ConfirmIdentity; confirmReveal: ConfirmIdentity } | null>(null);

/**
 * An open vault covers revealing and copying, however it was opened (maintainer decision, plan 03
 * History 2026-11-06): nothing asks while the session is unlocked. Only export, saving to a file,
 * the Secret Key, the Recovery Kit and the account's own settings ask (`useConfirmIdentity`).
 */
export async function unlockCoversReveal(service: VaultService): Promise<boolean> {
  return service.getSession().status === 'unlocked';
}

export function IdentityGateProvider({ children }: { children: ReactNode }) {
  const service = useService();
  const [request, setRequest] = useState<Request>();

  const confirm = useCallback<ConfirmIdentity>(
    async (options) => {
      // A host without the confirmation hook can't gate; the web vault, desktop and extension all have it.
      if (!service.confirmIdentity) return true;
      return new Promise<boolean>((resolve) => {
        setRequest((current) => {
          // Only one prompt at a time: a second click waits on the first answer.
          if (current) current.resolve(false);
          return { resolve, ...(options?.reason ? { reason: options.reason } : {}) };
        });
      });
    },
    [service],
  );

  const confirmReveal = useCallback<ConfirmIdentity>(
    async (options) => ((await unlockCoversReveal(service)) ? true : confirm(options)),
    [service, confirm],
  );
  const value = useMemo(() => ({ confirm, confirmReveal }), [confirm, confirmReveal]);

  function finish(confirmed: boolean) {
    request?.resolve(confirmed);
    setRequest(undefined);
  }

  return (
    <IdentityGateContext.Provider value={value}>
      {children}
      <ConfirmIdentityDialog open={request !== undefined} reason={request?.reason} onClose={() => finish(false)} onConfirmed={() => finish(true)} />
    </IdentityGateContext.Provider>
  );
}

const yes: ConfirmIdentity = async () => true;

/**
 * "Confirm it's you" every time: exports, the Secret Key, the Recovery Kit, the account's settings.
 * A harmless "yes" outside the provider, so a screen can render in isolation.
 */
export function useConfirmIdentity(): ConfirmIdentity {
  return useContext(IdentityGateContext)?.confirm ?? yes;
}

/**
 * Revealing and copying a secret, showing it as a QR code, and showing an SSH or certificate
 * private key: no prompt while the vault is open (`unlockCoversReveal`), "Confirm it's you" only
 * if it locked meanwhile. A harmless "yes" outside the provider.
 */
export function useConfirmReveal(): ConfirmIdentity {
  return useContext(IdentityGateContext)?.confirmReveal ?? yes;
}

function ConfirmIdentityDialog({ open, reason, onClose, onConfirmed }: { open: boolean; reason?: string; onClose: () => void; onConfirmed: () => void }) {
  const service = useService();
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [device, setDevice] = useState(false);
  const loaded = useRef(false);

  // `canConfirmIdentityWithDevice` runs in the worker; ask once per opening, before the user acts.
  useEffect(() => {
    if (!open) {
      loaded.current = false;
      setPassword('');
      setError(undefined);
      setBusy(false);
      return;
    }
    if (loaded.current) return;
    loaded.current = true;
    let live = true;
    void service.canConfirmIdentityWithDevice?.().then(
      (yes) => live && setDevice(yes),
      () => live && setDevice(false),
    );
    return () => {
      live = false;
    };
  }, [open, service]);

  async function confirm(proof: { password: string } | { device: true }) {
    setBusy(true);
    setError(undefined);
    try {
      await service.confirmIdentity!(proof);
      onConfirmed();
    } catch (e) {
      setError(isVaultError(e, 'invalidCredentials') ? t('identityGate.wrongPassword') : errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog
      open={open}
      onClose={onClose}
      closeLabel={t('common.close')}
      title={t('identityGate.title')}
      description={reason ?? t('identityGate.body')}
      footer={
        <>
          {device && (
            <Button variant="secondary" icon="fingerprint" disabled={busy} onClick={() => void confirm({ device: true })}>
              {t('identityGate.useDevice')}
            </Button>
          )}
          <Button type="submit" form="identity-gate" busy={busy} disabled={!password}>
            {t('identityGate.confirm')}
          </Button>
        </>
      }
    >
      <form
        id="identity-gate"
        className={styles.form}
        onSubmit={(e) => {
          e.preventDefault();
          void confirm({ password });
        }}
      >
        <PasswordInput
          label={device ? t('identityGate.passwordOrDevice') : t('fields.masterPassword')}
          autoComplete="current-password"
          autoFocus
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          error={error}
        />
        {device && <Alert tone="info">{t('identityGate.deviceHelp')}</Alert>}
      </form>
    </Dialog>
  );
}
