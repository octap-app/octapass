import { Switch, useToast } from '@octapass/ui';
import type { StayUnlockedStatus, UnlockMethods } from '@octapass/vault-client';
import { useEffect, useState } from 'react';
import { useService } from '../../app/ServiceContext';
import { useSettings } from '../../app/settings';
import { Alert } from '../../components/Alert';
import { t } from '../../i18n';
import { deviceMethodName } from '../../lib/deviceUnlock';
import { errorMessage } from '../../lib/errors';
import { useStayUnlocked } from '../../lib/stayUnlocked';
import { Row, Section } from './SettingsPage';
import styles from './SettingsPage.module.css';

/**
 * The two-gate device-auth settings (plan 03): ask when the app opens, and ask on every fill. Both
 * are per device and never synced. The web vault never offers a gateless mode, so it shows the rule
 * only. A device with no lock Octa Pass can use follows Google Password Manager: no prompt for
 * opening or filling, with the warning; reveal/copy/export still ask for the master password.
 *
 * Above them, where the host offers it, plan 18's "Stay unlocked while you're logged in to this
 * device": on, the gates show greyed out, since opening and filling don't ask.
 */
export function DeviceAuthSection({ autofill = false, webVault = false, local = false }: { autofill?: boolean; webVault?: boolean; local?: boolean }) {
  const service = useService();
  const { settings, update } = useSettings();
  const stay = useStayUnlocked();
  const [methods, setMethods] = useState<UnlockMethods>();

  useEffect(() => {
    let live = true;
    service.getUnlockMethods().then(
      (next) => live && setMethods(next),
      () => undefined,
    );
    return () => {
      live = false;
    };
  }, [service]);

  // The native side reads its own copy of the switch when it fills.
  const fillGate = settings.requireDeviceAuthOnAutofill;
  useEffect(() => void service.setFillGate?.(fillGate), [service, fillGate]);

  if (local && !service.setFillGate) {
    return (
      <Section title={t('deviceAuth.title')} description={t('deviceAuth.localOnly')}>
        <Row label={t('deviceAuth.revealHelp')} />
        {autofill && (
          <div className={styles.row}>
            <Switch label={t('deviceAuth.cvv')} description={t('deviceAuth.cvvHelp')} checked={settings.requireReauthForCvv} onChange={(requireReauthForCvv) => update({ requireReauthForCvv })} />
          </div>
        )}
      </Section>
    );
  }

  if (webVault) {
    return (
      <Section title={t('deviceAuth.title')} description={t('deviceAuth.webVault')}>
        <Row label={t('deviceAuth.revealHelp')} />
      </Section>
    );
  }

  // No device unlock *enrolled* means nothing to verify with here, whatever the OS supports.
  const lockless = methods !== undefined && !methods.deviceUnlockEnabled;
  // Plan 18: the two gates apply only with "Stay unlocked" off; while it's on they show greyed out.
  const staying = stay.status?.on === true && stay.status.available;

  return (
    <Section title={t('deviceAuth.title')}>
      {stay.status && <StayUnlockedRow status={stay.status} methods={methods} onChange={stay.set} />}
      <div className={styles.row}>
        <Switch
          label={t('deviceAuth.appOpen')}
          description={t('deviceAuth.appOpenHelp')}
          checked={settings.requireDeviceAuthOnAppOpen}
          disabled={lockless || staying}
          onChange={(requireDeviceAuthOnAppOpen) => update({ requireDeviceAuthOnAppOpen })}
        />
      </div>
      {autofill && (
        <div className={styles.row}>
          <Switch
            label={t('deviceAuth.autofill')}
            description={t('deviceAuth.autofillHelp')}
            checked={settings.requireDeviceAuthOnAutofill}
            disabled={lockless || staying}
            onChange={(requireDeviceAuthOnAutofill) => update({ requireDeviceAuthOnAutofill })}
          />
        </div>
      )}
      {staying && <Row label={t('deviceAuth.stayUnlockedGates')} />}
      {autofill && !staying && !settings.requireDeviceAuthOnAutofill && <Alert tone="warn">{t('deviceAuth.autofillOff')}</Alert>}
      {autofill && (
        <div className={styles.row}>
          <Switch label={t('deviceAuth.cvv')} description={t('deviceAuth.cvvHelp')} checked={settings.requireReauthForCvv} onChange={(requireReauthForCvv) => update({ requireReauthForCvv })} />
        </div>
      )}
      <Row label={t('deviceAuth.revealHelp')} />
      {lockless && <Alert tone="info">{t('deviceAuth.lockless')}</Alert>}
    </Section>
  );
}

/** Plan 18's switch, with what it means and why it can't be on here. */
function StayUnlockedRow({ status, methods, onChange }: { status: StayUnlockedStatus; methods?: UnlockMethods; onChange: (on: boolean) => Promise<void> }) {
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const on = status.on === true;
  // What "Confirm it's you" asks for: the device lock where device unlock is on, the master password otherwise.
  const method = !methods ? t('unlockOffer.device') : methods.deviceUnlockEnabled ? deviceMethodName(methods.platform) : t('deviceAuth.stayUnlockedPassword');
  const unavailable =
    status.unavailable === 'noKeyring' ? t('deviceAuth.stayUnlockedNoKeyring') : status.unavailable === 'noScreenLock' ? t('deviceAuth.stayUnlockedNoScreenLock') : t('deviceAuth.stayUnlockedNoPasscode');

  async function toggle(next: boolean) {
    setBusy(true);
    try {
      await onChange(next);
    } catch (e) {
      toast({ message: errorMessage(e), tone: 'danger' });
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <div className={styles.row}>
        <Switch
          label={t('deviceAuth.stayUnlocked')}
          description={!status.available ? unavailable : on ? t('deviceAuth.stayUnlockedOn', { method }) : undefined}
          checked={on && status.available}
          disabled={busy || !status.available}
          onChange={(next) => void toggle(next)}
        />
      </div>
      {on && status.available && status.browser && <Alert tone="info">{t('deviceAuth.stayUnlockedBrowser')}</Alert>}
      {on && status.available && status.passwordRequired && <Alert tone="info">{t('deviceAuth.stayUnlockedPasswordDue')}</Alert>}
    </>
  );
}
