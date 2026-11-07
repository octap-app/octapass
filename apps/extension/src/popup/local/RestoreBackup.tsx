import { Button, Segmented, TextField } from '@octapass/ui';
import { useService } from '@octapass/web/src/app/ServiceContext';
import { Alert } from '@octapass/web/src/components/Alert';
import { PasswordInput } from '@octapass/web/src/components/PasswordInput';
import { StrengthHint } from '@octapass/web/src/components/StrengthHint';
import { t } from '@octapass/web/src/i18n';
import { isVaultError } from '@octapass/vault-client';
import { errorMessage } from '@octapass/web/src/lib/errors';
import { AuthLayout } from '@octapass/web/src/screens/auth/AuthLayout';
import { useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router';
import { tx } from '../../i18n';
import { useExtension } from '../ExtensionContext';
import styles from './local.module.css';

type Secret = 'password' | 'code';

/** Opens a `.octapass-backup` file as this browser's vault, with its password or the recovery code. */
export function RestoreBackup() {
  const service = useService();
  const { api } = useExtension();
  const navigate = useNavigate();
  const [file, setFile] = useState<File>();
  const [secret, setSecret] = useState<Secret>('password');
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const estimate = service.estimateStrength(newPassword);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!file || (secret === 'password' ? !password : !code.trim() || estimate.score < 4)) {
      setError(secret === 'code' && code.trim() && newPassword ? tx('local.weak') : tx('local.restoreFailed'));
      return;
    }
    setBusy(true);
    setError(undefined);
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      if (secret === 'password') await api.restoreLocalBackup(bytes, { password }, password);
      else await api.restoreLocalBackup(bytes, { recoveryCode: code.trim() }, newPassword);
      navigate('/', { replace: true });
    } catch (e) {
      setError(isVaultError(e, 'invalidImportFile') ? tx('local.restoreFailed') : errorMessage(e));
      setBusy(false);
    }
  }

  return (
    <AuthLayout title={tx('local.restoreTitle')} subtitle={tx('local.restoreSubtitle')}>
      <form className={styles.form} onSubmit={submit} noValidate>
        {error && <Alert>{error}</Alert>}
        <label className={styles.file}>
          {tx('local.backupFile')}
          <input type="file" accept=".octapass-backup,application/octet-stream" onChange={(e) => setFile(e.target.files?.[0])} />
        </label>
        <Segmented<Secret>
          block
          label={tx('local.restoreTitle')}
          value={secret}
          onChange={setSecret}
          options={[
            { value: 'password', label: tx('local.withPassword') },
            { value: 'code', label: tx('local.withCode') },
          ]}
        />
        {secret === 'password' ? (
          <PasswordInput label={tx('local.backupPassword')} autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
        ) : (
          <>
            <TextField label={tx('local.recoveryCode')} mono spellCheck={false} autoComplete="off" value={code} onChange={(e) => setCode(e.target.value)} />
            <PasswordInput label={tx('local.newPassword')} autoComplete="new-password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} />
            <StrengthHint estimate={estimate} empty={!newPassword} />
          </>
        )}
        <Button type="submit" size="lg" block busy={busy}>
          {tx('local.restore')}
        </Button>
        <Button variant="ghost" onClick={() => navigate('/welcome')}>
          {t('common.back')}
        </Button>
      </form>
    </AuthLayout>
  );
}
