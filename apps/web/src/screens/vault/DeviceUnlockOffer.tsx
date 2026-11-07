import { Button, Dialog, useToast } from '@octapass/ui';
import { isVaultError, type UnlockMethods } from '@octapass/vault-client';
import { useEffect, useState } from 'react';
import { useService, useSession } from '../../app/ServiceContext';
import { t } from '../../i18n';
import { offerMethodName } from '../../lib/deviceUnlock';
import { errorMessage } from '../../lib/errors';

/** `declined`: Not now, reminded at the next unlock. `done`: turned on or reminded; never asked again. */
type OfferState = 'declined' | 'done';

const storageKey = (email: string) => `octapass.deviceUnlockOffer:${email}`;

function readState(email: string): OfferState | undefined {
  try {
    return (localStorage.getItem(storageKey(email)) as OfferState | null) ?? undefined;
  } catch {
    return undefined;
  }
}

function writeState(email: string, state: OfferState) {
  try {
    localStorage.setItem(storageKey(email), state);
  } catch {
    // Offered again next time.
  }
}

/**
 * Right after sign-in or sign-up in the apps (plan 03): "Use Face ID to unlock Octa Pass?". Turning
 * it on runs the system's check once. Not now asks once more at a later unlock (each mount is one
 * master-password unlock, since device unlock is off), then never again.
 */
export function DeviceUnlockOffer() {
  const service = useService();
  const { email } = useSession();
  const toast = useToast();
  const [methods, setMethods] = useState<UnlockMethods>();
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!email) return;
    const state = readState(email);
    if (state === 'done') return;
    let live = true;
    void service.getUnlockMethods().then(
      (next) => {
        if (!live || !next.deviceUnlockSupported || next.deviceUnlockEnabled) return;
        // The reminder is the last time.
        if (state === 'declined') writeState(email, 'done');
        setMethods(next);
      },
      () => {},
    );
    return () => {
      live = false;
    };
  }, [service, email]);

  if (!methods || !email) return null;
  const method = offerMethodName(methods);

  const notNow = () => {
    if (readState(email) !== 'done') writeState(email, 'declined');
    setMethods(undefined);
  };

  async function turnOn() {
    setBusy(true);
    try {
      await service.enableDeviceUnlock();
      writeState(email!, 'done');
      setMethods(undefined);
      toast({ message: t('unlockOffer.enabled', { method }), tone: 'success' });
    } catch (e) {
      // Cancelling the system prompt is the same as Not now.
      if (isVaultError(e, 'deviceUnlockCancelled')) return notNow();
      toast({ message: errorMessage(e), tone: 'danger' });
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog
      open
      onClose={busy ? () => undefined : notNow}
      closeLabel={t('common.close')}
      title={t('unlockOffer.title', { method })}
      description={t('unlockOffer.body', { method })}
      footer={
        <>
          <Button variant="ghost" onClick={notNow} disabled={busy}>
            {t('unlockOffer.notNow')}
          </Button>
          <Button onClick={() => void turnOn()} busy={busy}>
            {t('unlockOffer.turnOn')}
          </Button>
        </>
      }
    />
  );
}
