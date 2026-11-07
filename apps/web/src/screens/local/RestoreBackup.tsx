import { Button, Segmented, TextField } from '@octapass/ui';
import { useState, type FormEvent } from 'react';
import { Navigate, useNavigate } from 'react-router';
import { useService } from '../../app/ServiceContext';
import { Alert } from '../../components/Alert';
import { PasswordInput } from '../../components/PasswordInput';
import { StrengthHint } from '../../components/StrengthHint';
import { t } from '../../i18n';
import { errorMessage } from '../../lib/errors';
import { AuthLayout } from '../auth/AuthLayout';
import styles from './local.module.css';

type Secret = 'password' | 'code';

/** Opens a `.octapass-backup` file as a new vault here, with its password or the recovery code. */
export function RestoreBackup() {
  const service = useService();
  const navigate = useNavigate();
  const [file, setFile] = useState<File>();
  const [secret, setSecret] = useState<Secret>('password');
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const estimate = service.estimateStrength(newPassword);
  if (!service.local) return <Navigate to="/" replace />;
  const local = service.local;

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!file || (secret === 'password' ? !password : !code.trim() || !newPassword)) {
      setError(t('localVault.restoreFailed'));
      return;
    }
    setBusy(true);
    setError(undefined);
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      await local.restore(bytes, secret === 'password' ? { password } : { recoveryCode: code.trim(), newPassword });
      navigate('/', { replace: true });
    } catch (e) {
      setError(errorMessage(e));
      setBusy(false);
    }
  }

  return (
    <AuthLayout title={t('localVault.restoreTitle')} subtitle={t('localVault.restoreSubtitle')}>
      <form className={styles.form} onSubmit={submit} noValidate>
        {error && <Alert>{error}</Alert>}
        <label className={styles.file}>
          {t('localVault.backupFile')}
          <input type="file" accept=".octapass-backup,application/octet-stream" onChange={(e) => setFile(e.target.files?.[0])} />
        </label>
        <Segmented<Secret>
          block
          label={t('localVault.restoreTitle')}
          value={secret}
          onChange={setSecret}
          options={[
            { value: 'password', label: t('localVault.withPassword') },
            { value: 'code', label: t('localVault.withCode') },
          ]}
        />
        {secret === 'password' ? (
          <PasswordInput label={t('localVault.backupPassword')} autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
        ) : (
          <>
            <TextField label={t('localVault.recoveryCode')} mono spellCheck={false} autoComplete="off" value={code} onChange={(e) => setCode(e.target.value)} />
            <PasswordInput label={t('localVault.newPassword')} autoComplete="new-password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} />
            <StrengthHint estimate={estimate} empty={!newPassword} />
          </>
        )}
        <Button type="submit" size="lg" block busy={busy}>
          {t('localVault.restore')}
        </Button>
        <Button variant="ghost" onClick={() => navigate('/welcome')}>
          {t('common.back')}
        </Button>
      </form>
    </AuthLayout>
  );
}
