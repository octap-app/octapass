import { Button, Dialog } from '@octapass/ui';
import { useEffect, useState, type ReactNode } from 'react';
import { t } from '../i18n';
import { errorMessage } from '../lib/errors';
import { Alert } from './Alert';

export interface ConfirmDialogProps {
  open: boolean;
  title: string;
  children: ReactNode;
  confirmLabel: string;
  tone?: 'danger' | 'primary';
  /** Closes on success; a rejection is shown in the dialog. */
  onConfirm: () => Promise<void>;
  onClose: () => void;
}

/** Asks before something that can't be undone, and stays open with the reason if it fails. */
export function ConfirmDialog({ open, title, children, confirmLabel, tone = 'danger', onConfirm, onClose }: ConfirmDialogProps) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();

  useEffect(() => {
    if (open) setError(undefined);
  }, [open]);

  async function confirm() {
    setBusy(true);
    setError(undefined);
    try {
      await onConfirm();
      onClose();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog
      open={open}
      onClose={busy ? () => undefined : onClose}
      closeLabel={t('common.close')}
      title={title}
      footer={
        <>
          <Button variant="secondary" disabled={busy} onClick={onClose}>
            {t('common.cancel')}
          </Button>
          <Button variant={tone} busy={busy} onClick={() => void confirm()}>
            {confirmLabel}
          </Button>
        </>
      }
    >
      <p>{children}</p>
      {error && <Alert>{error}</Alert>}
    </Dialog>
  );
}
