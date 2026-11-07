import { Button, Dialog, Icon, Spinner, TextField } from '@octapass/ui';
import { normalizeEmail, type AccountSummary } from '@octapass/vault-client';
import { useEffect, useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router';
import { useExitTo, useService } from '../../app/ServiceContext';
import { Alert } from '../../components/Alert';
import { PasswordInput } from '../../components/PasswordInput';
import { t } from '../../i18n';
import { errorMessage } from '../../lib/errors';
import { wipeLocalPreferences } from '../../lib/wipe';
import { useExport } from './ExportDialog';
import styles from './DeleteAccount.module.css';

/**
 * Settings → Account → Delete account (plan 11, "Account deletion"): explain what goes, offer an
 * export, then confirm with the account email and a fresh master password check.
 */
export function DeleteAccount({ open, onClose }: { open: boolean; onClose: () => void }) {
  const service = useService();
  const navigate = useNavigate();
  const exitTo = useExitTo();
  const exportVault = useExport();
  const [summary, setSummary] = useState<AccountSummary>();
  const [loadError, setLoadError] = useState<string>();
  const [step, setStep] = useState<'summary' | 'confirm'>('summary');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!open) return;
    setStep('summary');
    setEmail('');
    setPassword('');
    setError(undefined);
    let live = true;
    service.getAccountSummary().then(
      (next) => live && setSummary(next),
      (e: unknown) => live && setLoadError(errorMessage(e)),
    );
    return () => {
      live = false;
    };
  }, [open, service]);

  const emailMatches = summary !== undefined && normalizeEmail(email) === summary.email;

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!emailMatches || !password) return;
    setBusy(true);
    setError(undefined);
    // Set before the session ends so the route guards send us to the goodbye screen, not sign-in.
    exitTo.current = '/deleted';
    try {
      await service.deleteAccount({ confirmEmail: email, password });
      wipeLocalPreferences();
      navigate('/deleted', { replace: true });
    } catch (e) {
      exitTo.current = null;
      setError(errorMessage(e));
      setPassword('');
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onClose={busy ? () => undefined : onClose} closeLabel={t('common.close')} title={t('deleteAccount.title')} size="md">
      {!summary ? (
        loadError ? (
          <Alert>{loadError}</Alert>
        ) : (
          <div className={styles.loading}>
            <Spinner size={22} />
          </div>
        )
      ) : step === 'summary' ? (
        <div className={styles.step}>
          <p>{t('deleteAccount.intro')}</p>
          <ul className={styles.facts}>
            <li>
              <Icon name="key" size={18} />
              {t('deleteAccount.items', { count: summary.itemCount })} {t('deleteAccount.vaults', { count: summary.vaultCount })}
            </li>
            <li>
              <Icon name="monitor" size={18} />
              {t('deleteAccount.devices', { count: summary.deviceCount })}
            </li>
            <li>
              <Icon name="mail" size={18} />
              {t('deleteAccount.emailFreed', { email: summary.email })}
            </li>
          </ul>
          {summary.sharedVaultsOwned.length > 0 && (
            <Alert tone="warn">
              {t('deleteAccount.sharedVaults', { count: summary.sharedVaultsOwned.length, vaults: summary.sharedVaultsOwned.join(', ') })}
            </Alert>
          )}
          <Alert>{t('deleteAccount.permanent')}</Alert>
          <div className={styles.export}>
            <p>{t('deleteAccount.exportFirst')}</p>
            <div className={styles.exportButtons}>
              <Button variant="secondary" size="sm" icon="download" onClick={() => void exportVault('json')}>
                {t('settings.formatJson')}
              </Button>
              <Button variant="secondary" size="sm" icon="download" onClick={() => void exportVault('csv')}>
                {t('settings.formatCsv')}
              </Button>
            </div>
          </div>
          <div className={styles.footer}>
            <Button variant="secondary" onClick={onClose}>
              {t('deleteAccount.keep')}
            </Button>
            <Button variant="secondary" onClick={() => setStep('confirm')}>
              {t('deleteAccount.continue')}
            </Button>
          </div>
        </div>
      ) : (
        <form className={styles.step} onSubmit={submit} noValidate>
          <p>{t('deleteAccount.confirmIntro')}</p>
          {error && <Alert>{error}</Alert>}
          <TextField
            label={t('deleteAccount.typeEmail', { email: summary.email })}
            type="email"
            autoComplete="off"
            spellCheck={false}
            autoFocus
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            error={email && !emailMatches && normalizeEmail(email).length >= summary.email.length ? t('errors.emailMismatch') : undefined}
          />
          <PasswordInput label={t('fields.masterPassword')} autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
          <div className={styles.footer}>
            <Button variant="secondary" disabled={busy} onClick={() => setStep('summary')}>
              {t('common.back')}
            </Button>
            <button type="submit" className={styles.destroy} disabled={!emailMatches || !password || busy} aria-busy={busy || undefined}>
              {busy ? <Spinner size={18} /> : <Icon name="trash" size={18} />}
              {t('deleteAccount.confirm')}
            </button>
          </div>
        </form>
      )}
    </Dialog>
  );
}
