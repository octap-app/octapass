import { Button, Checkbox, Icon, TextField, useToast } from '@octapass/ui';
import type { LocalCapabilities } from '@octapass/vault-client';
import { useEffect, useState, type FormEvent } from 'react';
import { Navigate, useNavigate } from 'react-router';
import { useService, useSession } from '../../app/ServiceContext';
import { Alert } from '../../components/Alert';
import { PasswordInput } from '../../components/PasswordInput';
import { StrengthHint } from '../../components/StrengthHint';
import { t } from '../../i18n';
import { errorMessage } from '../../lib/errors';
import { AuthLayout } from '../auth/AuthLayout';
import signUp from '../auth/SignUp.module.css';
import styles from './local.module.css';
import { RecoveryCode } from './RecoveryCode';

/** "Use on this device only": a name and a master password, the recovery code, then a first backup. */
export function CreateLocal() {
  const service = useService();
  const session = useSession();
  const [code, setCode] = useState<string>();
  const [kept, setKept] = useState(false);
  if (kept) return <FirstBackup />;
  if (code) return <LocalKit code={code} onDone={() => setKept(true)} />;
  // Creating unlocks the new vault, so this screen guards itself rather than through RequireSignedOut.
  if (!service.local || session.status !== 'signedOut') return <Navigate to="/" replace />;
  return <PasswordStep onCreated={setCode} />;
}

function PasswordStep({ onCreated }: { onCreated: (code: string) => void }) {
  const service = useService();
  const local = service.local!;
  const [capabilities, setCapabilities] = useState<LocalCapabilities>();
  const [name, setName] = useState(t('localVault.defaultName'));
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [errors, setErrors] = useState<{ name?: string; password?: string; confirm?: string }>({});
  const [formError, setFormError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const estimate = service.estimateStrength(password);
  useEffect(() => void local.capabilities().then(setCapabilities), [local]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    const next: typeof errors = {};
    if (!name.trim()) next.name = t('errors.invalidName');
    if (estimate.score < (capabilities?.minScore ?? 4)) next.password = password ? t('localVault.weak') : t('validation.passwordRequired');
    if (confirm !== password) next.confirm = t('validation.passwordsDontMatch');
    setErrors(next);
    setFormError(undefined);
    if (Object.keys(next).length) return;
    setBusy(true);
    try {
      onCreated(await local.create({ name, password }));
    } catch (e) {
      setFormError(errorMessage(e));
      setBusy(false);
    }
  }

  return (
    <AuthLayout title={t('localVault.createTitle')} subtitle={t('localVault.createSubtitle')}>
      <form className={signUp.form} onSubmit={submit} noValidate>
        {formError && <Alert>{formError}</Alert>}
        <TextField label={t('localVault.nameLabel')} hint={t('localVault.nameHint')} value={name} onChange={(e) => setName(e.target.value)} error={errors.name} />
        <div className={signUp.passwordGroup}>
          <PasswordInput label={t('fields.masterPassword')} autoComplete="new-password" autoFocus value={password} onChange={(e) => setPassword(e.target.value)} error={errors.password} />
          <StrengthHint estimate={estimate} empty={!password} />
        </div>
        <PasswordInput label={t('fields.confirmPassword')} autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} error={errors.confirm} />
        <div className={signUp.guidance}>
          <Icon name="info" size={18} />
          <p>
            {t('localVault.guidance')} {capabilities?.chip && t('localVault.guidanceChip')}
          </p>
        </div>
        <Button type="submit" size="lg" block busy={busy}>
          {busy ? t('localVault.creating') : t('localVault.create')}
        </Button>
      </form>
    </AuthLayout>
  );
}

function LocalKit({ code, onDone }: { code: string; onDone: () => void }) {
  const [saved, setSaved] = useState(false);
  return (
    <AuthLayout title={t('localVault.kitTitle')} subtitle={t('localVault.kitSubtitle')}>
      <RecoveryCode code={code} />
      <div className={signUp.confirm}>
        <Checkbox label={t('localVault.kitConfirm')} checked={saved} onChange={(e) => setSaved(e.target.checked)} />
      </div>
      <Button size="lg" block disabled={!saved} onClick={onDone}>
        {t('localVault.kitContinue')}
      </Button>
    </AuthLayout>
  );
}

/** Prompted on first setup (plan 01): a file now, a folder for automatic backups, or later. */
function FirstBackup() {
  const service = useService();
  const local = service.local!;
  const navigate = useNavigate();
  const toast = useToast();
  const [error, setError] = useState<string>();
  const open = () => navigate('/', { replace: true });

  async function run(action: () => Promise<string | undefined>, done: string) {
    setError(undefined);
    try {
      if (!(await action())) return;
      toast({ message: done, tone: 'success', icon: 'download' });
      open();
    } catch (e) {
      setError(errorMessage(e));
    }
  }

  return (
    <AuthLayout title={t('localVault.firstBackupTitle')} subtitle={t('localVault.firstBackupSubtitle')}>
      <div className={styles.stack}>
        {error && <Alert>{error}</Alert>}
        <Button size="lg" block icon="download" onClick={() => void run(local.saveBackup, t('localVault.backedUp'))}>
          {t('localVault.backUp')}
        </Button>
        <Button size="lg" block variant="secondary" onClick={() => void run(local.chooseBackupFolder, t('localVault.folderChosen'))}>
          {t('localVault.chooseFolder')}
        </Button>
        <Button size="lg" block variant="ghost" onClick={open}>
          {t('localVault.firstBackupLater')}
        </Button>
      </div>
    </AuthLayout>
  );
}
