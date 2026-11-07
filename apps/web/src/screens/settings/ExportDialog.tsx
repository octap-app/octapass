import { Button, Dialog, Segmented, useToast } from '@octapass/ui';
import type { ExportFormat, ExportOptions } from '@octapass/vault-client';
import { useEffect, useState, type FormEvent } from 'react';
import { useService } from '../../app/ServiceContext';
import { Alert } from '../../components/Alert';
import { PasswordInput } from '../../components/PasswordInput';
import { t, type MessageKey } from '../../i18n';
import { downloadBlob } from '../../lib/download';
import { errorMessage } from '../../lib/errors';
import { useConfirmIdentity } from '../../lib/identityGate';

/** The encrypted export's password: anyone with the file can try guesses offline. */
export const MIN_EXPORT_PASSWORD = 10;

const EXTENSIONS: Record<ExportFormat, string> = { encrypted: 'octapass', json: 'json', csv: 'csv', cxf: 'cxf.json' };

export function exportFilename(format: ExportFormat, now = new Date()): string {
  return `octapass-export-${now.toISOString().slice(0, 10)}.${EXTENSIONS[format]}`;
}

/** Downloads the vault. Shared by Settings and the account deletion flow ("export first"). */
export function useExport(): (format: ExportFormat, options?: ExportOptions) => Promise<boolean> {
  const service = useService();
  const toast = useToast();
  return async (format, options) => {
    try {
      downloadBlob(await service.exportVault(format, options), exportFilename(format));
      toast({ message: t('settings.exported'), tone: 'success', icon: 'download' });
      return true;
    } catch (e) {
      toast({ message: errorMessage(e), tone: 'danger' });
      return false;
    }
  };
}

const FORMATS: { value: ExportFormat; label: MessageKey; help: MessageKey }[] = [
  { value: 'encrypted', label: 'export.formatEncrypted', help: 'export.encryptedHelp' },
  { value: 'json', label: 'settings.formatJson', help: 'settings.jsonHelp' },
  { value: 'csv', label: 'settings.formatCsv', help: 'settings.csvHelp' },
  { value: 'cxf', label: 'export.formatCxf', help: 'export.cxfHelp' },
];

/**
 * Settings → Export: pick a format, confirm it's you (device auth, or the master password, plan 07),
 * and for the encrypted export choose a password for the file.
 */
export function ExportDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [format, setFormat] = useState<ExportFormat>('encrypted');
  const [password, setPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const exportVault = useExport();
  const confirm = useConfirmIdentity();
  const encrypted = format === 'encrypted';

  useEffect(() => {
    if (!open) return;
    setPassword('');
    setConfirmation('');
    setError(undefined);
  }, [open]);

  function problem(): string | undefined {
    if (!encrypted) return undefined;
    if (password.length < MIN_EXPORT_PASSWORD) return t('export.passwordTooShort', { count: MIN_EXPORT_PASSWORD });
    if (password !== confirmation) return t('export.passwordMismatch');
    return undefined;
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    const found = problem();
    setError(found);
    if (found) return;
    // Revealing everything is a sensitive action: a fresh device check, or the master password.
    if (!(await confirm({ reason: t('identityGate.body') }))) return;
    setBusy(true);
    const done = await exportVault(format, encrypted ? { password } : undefined);
    setBusy(false);
    if (done) onClose();
  }

  const selected = FORMATS.find((f) => f.value === format)!;
  return (
    <Dialog
      open={open}
      onClose={onClose}
      closeLabel={t('common.close')}
      title={t('settings.exportTitle')}
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            {t('common.cancel')}
          </Button>
          <Button icon="download" busy={busy} type="submit" form="export-form">
            {t('settings.exportAction')}
          </Button>
        </>
      }
    >
      <form id="export-form" onSubmit={submit} noValidate>
        <Segmented block label={t('settings.exportFormat')} value={format} onChange={setFormat} options={FORMATS.map((f) => ({ value: f.value, label: t(f.label) }))} />
        <p>{t(selected.help)}</p>
        {encrypted ? (
          <>
            <PasswordInput label={t('export.password')} autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} />
            <PasswordInput label={t('export.confirmPassword')} autoComplete="new-password" value={confirmation} onChange={(e) => setConfirmation(e.target.value)} />
            <Alert tone="info">{t('export.encryptedNote')}</Alert>
          </>
        ) : (
          <Alert tone="warn">{t('settings.exportWarning')}</Alert>
        )}
        {error && <Alert>{error}</Alert>}
      </form>
    </Dialog>
  );
}
