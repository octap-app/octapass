import { Button, Checkbox, Dialog, Icon, IconButton, Spinner, TextField, useToast } from '@octapass/ui';
import { isVaultError, type SecurityKeyInfo, type TotpSetup, type TwoStepStatus } from '@octapass/vault-client';
import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { useService } from '../../app/ServiceContext';
import { Alert } from '../../components/Alert';
import { PasswordInput } from '../../components/PasswordInput';
import { QrCode } from '../../components/QrCode';
import { formatDate, t, type MessageKey } from '../../i18n';
import { useCopy } from '../../lib/clipboard';
import { errorMessage } from '../../lib/errors';
import sharingStyles from '../sharing/Sharing.module.css';
import { Row, Section } from './SettingsPage';
import styles from './TwoStep.module.css';

type Kind = 'enable' | 'change' | 'addKey' | 'removeKey' | 'renew' | 'disable';
type Flow = { kind: Exclude<Kind, 'removeKey'> } | { kind: 'removeKey'; key: SecurityKeyInfo };

const CONFIRM: Record<Kind, MessageKey> = {
  enable: 'twoStepSettings.continue',
  change: 'twoStepSettings.continue',
  addKey: 'twoStepSettings.addKey',
  removeKey: 'common.remove',
  renew: 'twoStepSettings.newCodes',
  disable: 'twoStepSettings.turnOff',
};

/**
 * Settings → Two-step sign-in (plan 03, "Account 2FA"): on with an authenticator app, then optional
 * security keys, recovery codes, and off again. Every change asks for the master password.
 */
export function TwoStepSection() {
  const service = useService();
  const twoStep = service.twoStep;
  const [status, setStatus] = useState<TwoStepStatus>();
  const [loadError, setLoadError] = useState<string>();
  const [flow, setFlow] = useState<Flow>();
  const [forgetting, setForgetting] = useState(false);
  const toast = useToast();

  const reload = useCallback(() => {
    if (!twoStep) return () => undefined;
    let live = true;
    twoStep.getTwoStepStatus().then(
      (next) => live && setStatus(next),
      (e: unknown) => live && setLoadError(errorMessage(e)),
    );
    return () => {
      live = false;
    };
  }, [twoStep]);
  useEffect(reload, [reload]);

  if (!twoStep) return null;

  async function forgetDevices() {
    setForgetting(true);
    try {
      await twoStep!.forgetTrustedDevices!();
      toast({ message: t('twoStepSettings.devicesForgotten'), tone: 'success' });
    } catch (e) {
      toast({ message: errorMessage(e), tone: 'danger' });
    } finally {
      setForgetting(false);
    }
  }

  return (
    <Section id="two-step" title={t('settings.twoStep')} description={t('settings.twoStepHelp')}>
      {!status ? (
        <p className={sharingStyles.empty}>{loadError ?? <Spinner size={18} />}</p>
      ) : !status.enabled ? (
        <Row label={t('twoStepSettings.status')} description={t('twoStepSettings.off')}>
          <Button size="sm" icon="shield" onClick={() => setFlow({ kind: 'enable' })}>
            {t('twoStepSettings.turnOn')}
          </Button>
        </Row>
      ) : (
        <>
          <Row label={t('twoStepSettings.authenticator')} description={t('twoStepSettings.authenticatorOn')}>
            <Button variant="secondary" size="sm" icon="phone" onClick={() => setFlow({ kind: 'change' })}>
              {t('twoStepSettings.change')}
            </Button>
          </Row>
          <Row
            label={t('twoStepSettings.securityKeys')}
            description={status.securityKeysSupported ? t('twoStepSettings.securityKeysHelp') : t('twoStepSettings.securityKeysUnsupported')}
          >
            {status.securityKeysSupported && (
              <Button variant="secondary" size="sm" icon="plus" onClick={() => setFlow({ kind: 'addKey' })}>
                {t('twoStepSettings.addKey')}
              </Button>
            )}
          </Row>
          {status.securityKeys.length > 0 && (
            <ul className={`${sharingStyles.list} ${styles.keys}`} aria-label={t('twoStepSettings.securityKeys')}>
              {status.securityKeys.map((key) => (
                <li key={key.id} className={sharingStyles.person}>
                  <div className={sharingStyles.who}>
                    <span className={sharingStyles.vaultIcon}>
                      <Icon name="passkey" size={18} />
                    </span>
                    <div className={sharingStyles.whoText}>
                      <span className={sharingStyles.name}>{key.name}</span>
                      <span className={sharingStyles.meta}>
                        <span>{t('twoStepSettings.keyAdded', { date: formatDate(key.createdAt) })}</span>
                        {key.lastUsedAt && <span>{t('twoStepSettings.keyUsed', { date: formatDate(key.lastUsedAt) })}</span>}
                      </span>
                    </div>
                  </div>
                  <div className={sharingStyles.controls}>
                    <IconButton icon="trash" size="sm" label={t('twoStepSettings.removeKey', { name: key.name })} onClick={() => setFlow({ kind: 'removeKey', key })} />
                  </div>
                </li>
              ))}
            </ul>
          )}
          <Row label={t('twoStepSettings.recoveryCodes')} description={t('twoStepSettings.recoveryCodesLeft', { count: status.recoveryCodesLeft })}>
            <Button variant="secondary" size="sm" icon="refresh" onClick={() => setFlow({ kind: 'renew' })}>
              {t('twoStepSettings.newCodes')}
            </Button>
          </Row>
          {twoStep.forgetTrustedDevices && (
            <Row label={t('twoStepSettings.otherDevices')} description={t('twoStepSettings.otherDevicesHelp')}>
              <Button variant="secondary" size="sm" icon="monitor" busy={forgetting} onClick={forgetDevices}>
                {t('twoStepSettings.forgetDevices')}
              </Button>
            </Row>
          )}
          <Row label={t('twoStepSettings.turnOff')} description={t('twoStepSettings.turnOffHelp')}>
            <Button variant="danger" size="sm" onClick={() => setFlow({ kind: 'disable' })}>
              {t('twoStepSettings.turnOff')}
            </Button>
          </Row>
        </>
      )}
      {flow && <TwoStepDialog key={flow.kind} flow={flow} onClose={() => setFlow(undefined)} onChanged={reload} />}
    </Section>
  );
}

function TwoStepDialog({ flow, onClose, onChanged }: { flow: Flow; onClose: () => void; onChanged: () => void }) {
  const twoStep = useService().twoStep!;
  const toast = useToast();
  const copy = useCopy();
  const [step, setStep] = useState<'password' | 'scan' | 'codes'>('password');
  const [password, setPassword] = useState('');
  const [keyName, setKeyName] = useState(t('twoStepSettings.keyNameDefault'));
  const [setup, setSetup] = useState<TotpSetup>();
  const [code, setCode] = useState('');
  const [codes, setCodes] = useState<string[]>([]);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string>();
  const [fieldError, setFieldError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const keyLabel = flow.kind === 'removeKey' ? flow.key.name : '';

  function finished(message: string) {
    toast({ message, tone: 'success' });
    onChanged();
    onClose();
  }

  async function submitPassword(event: FormEvent) {
    event.preventDefault();
    if (!password) return setFieldError(t('validation.passwordRequired'));
    if (flow.kind === 'addKey' && !keyName.trim()) return setError(t('twoStepSettings.keyNameRequired'));
    setBusy(true);
    setError(undefined);
    setFieldError(undefined);
    try {
      switch (flow.kind) {
        case 'enable':
        case 'change':
          setSetup(await twoStep.startTotpSetup(password));
          setStep('scan');
          break;
        case 'renew':
          setCodes(await twoStep.renewRecoveryCodes(password));
          setStep('codes');
          onChanged();
          break;
        case 'addKey': {
          const key = await twoStep.addSecurityKey({ password, name: keyName.trim() });
          finished(t('twoStepSettings.keyAddedToast', { name: key.name }));
          break;
        }
        case 'removeKey':
          await twoStep.removeSecurityKey({ id: flow.key.id, password });
          finished(t('twoStepSettings.keyRemoved', { name: flow.key.name }));
          break;
        case 'disable':
          await twoStep.disableTwoStep(password);
          finished(t('twoStepSettings.turnedOff'));
          break;
      }
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setPassword('');
      setBusy(false);
    }
  }

  async function confirmCode(event: FormEvent) {
    event.preventDefault();
    const typed = code.replace(/\s/g, '');
    if (!/^\d{6}$/.test(typed)) return setFieldError(t('twoStep.codeRequired'));
    setBusy(true);
    setError(undefined);
    setFieldError(undefined);
    try {
      const { recoveryCodes } = await twoStep.confirmTotpSetup(typed);
      if (recoveryCodes) {
        onChanged();
        setCodes(recoveryCodes);
        setStep('codes');
      } else {
        finished(t('twoStepSettings.changed'));
      }
    } catch (e) {
      if (isVaultError(e, 'invalidTwoStepCode')) {
        setFieldError(errorMessage(e));
        setCode('');
      } else if (isVaultError(e, 'twoStepExpired')) {
        setStep('password');
        setError(t('twoStepSettings.setupExpired'));
      } else {
        setError(errorMessage(e));
      }
    } finally {
      setBusy(false);
    }
  }

  function done() {
    if (flow.kind === 'enable') toast({ message: t('twoStepSettings.turnedOn'), tone: 'success' });
    onClose();
  }

  // Recovery codes are shown once: closing waits until they're saved.
  const closable = !busy && (step !== 'codes' || saved);
  const danger = flow.kind === 'disable' || flow.kind === 'removeKey';

  return (
    <Dialog open onClose={closable ? onClose : () => undefined} closeLabel={t('common.close')} title={t(`twoStepSettings.titles.${flow.kind}`)} size="md">
      {step === 'password' && (
        <form className={styles.step} onSubmit={submitPassword} noValidate>
          <p>{t(`twoStepSettings.passwordIntro.${flow.kind}`, { name: keyLabel })}</p>
          {error && <Alert>{error}</Alert>}
          {flow.kind === 'addKey' && <TextField label={t('twoStepSettings.keyName')} maxLength={64} value={keyName} onChange={(e) => setKeyName(e.target.value)} />}
          <PasswordInput
            label={t('fields.masterPassword')}
            autoComplete="current-password"
            autoFocus
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            error={fieldError}
          />
          {flow.kind === 'addKey' && busy && (
            <p className={styles.hint} role="status">
              {t('twoStepSettings.keyPrompt')}
            </p>
          )}
          <div className={styles.footer}>
            <Button variant="secondary" disabled={busy} onClick={onClose}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" variant={danger ? 'danger' : 'primary'} busy={busy}>
              {t(CONFIRM[flow.kind])}
            </Button>
          </div>
        </form>
      )}

      {step === 'scan' && setup && (
        <form className={styles.step} onSubmit={confirmCode} noValidate>
          <p>{t('twoStepSettings.scan')}</p>
          <div className={styles.qr}>
            <QrCode value={setup.otpauthUri} size={176} label={t('twoStepSettings.qrLabel')} />
          </div>
          <div className={styles.setupKey}>
            <span>{t('twoStepSettings.typeInstead')}</span>
            <span className={styles.secret}>
              <code className="mono" aria-label={t('twoStepSettings.setupKey')}>
                {setup.secret.match(/.{1,4}/g)!.join(' ')}
              </code>
              <IconButton icon="copy" size="sm" label={t('copy.action', { what: t('twoStepSettings.setupKey') })} onClick={() => void copy(setup.secret, t('twoStepSettings.setupKey'))} />
            </span>
          </div>
          <p>{t('twoStepSettings.confirmCode')}</p>
          {error && <Alert>{error}</Alert>}
          <TextField
            label={t('twoStep.codeLabel')}
            mono
            autoComplete="one-time-code"
            inputMode="numeric"
            pattern="[0-9 ]*"
            maxLength={7}
            autoFocus
            value={code}
            onChange={(e) => setCode(e.target.value)}
            error={fieldError}
          />
          <div className={styles.footer}>
            <Button variant="secondary" disabled={busy} onClick={onClose}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" busy={busy}>
              {flow.kind === 'enable' ? t('twoStepSettings.confirm') : t('twoStepSettings.confirmChange')}
            </Button>
          </div>
        </form>
      )}

      {step === 'codes' && (
        <div className={styles.step}>
          <p>{t('twoStepSettings.saveCodes')}</p>
          <ol className={styles.codes} aria-label={t('twoStepSettings.codesLabel')}>
            {codes.map((c) => (
              <li key={c} className="mono">
                {c}
              </li>
            ))}
          </ol>
          <div>
            <Button variant="secondary" size="sm" icon="copy" onClick={() => void copy(codes.join('\n'), t('twoStepSettings.codesLabel'))}>
              {t('twoStepSettings.copyCodes')}
            </Button>
          </div>
          <Checkbox label={t('twoStepSettings.saved')} checked={saved} onChange={(e) => setSaved(e.target.checked)} />
          <div className={styles.footer}>
            <Button disabled={!saved} onClick={done}>
              {t('twoStepSettings.done')}
            </Button>
          </div>
        </div>
      )}
    </Dialog>
  );
}
