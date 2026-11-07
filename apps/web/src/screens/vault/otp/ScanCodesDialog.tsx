import { Button, Dialog, Spinner, useToast } from '@octapass/ui';
import type { ImportReview, QrCaptureSource } from '@octapass/vault-client';
import { useEffect, useRef, useState } from 'react';
import { useService } from '../../../app/ServiceContext';
import { Alert } from '../../../components/Alert';
import { t } from '../../../i18n';
import { errorMessage } from '../../../lib/errors';
import { codeLinks, ImportReviewList, initialChoices, type CodeChoices } from './ImportReviewList';
import { useLogins } from './LoginPicker';
import { MissingParts, QrCapture } from './QrCapture';
import { codeLabel, useQrScan } from './useQrScan';
import styles from './otp.module.css';

export interface ScanCodesDialogProps {
  open: boolean;
  onClose: () => void;
  /** QR texts already scanned (the phone's camera, the extension's image menu). */
  initialTexts?: string[];
  /** Scans from this source as soon as it opens (the extension's "Scan QR code on this page"). */
  autoCapture?: QrCaptureSource;
  /** The first step's title and description, when the codes came another way (a link the phone opened). */
  title?: string;
  description?: string;
}

/**
 * New one-time codes from QR codes: a site's setup code, or every account of a Google
 * Authenticator export (all its QR codes). Then each code joins a login or becomes its own item.
 */
export function ScanCodesDialog({ open, ...props }: ScanCodesDialogProps) {
  return open ? <ScanCodes {...props} /> : null;
}

function ScanCodes({ onClose, initialTexts, autoCapture, title, description }: Omit<ScanCodesDialogProps, 'open'>) {
  const service = useService();
  const toast = useToast();
  const scanner = useQrScan(initialTexts);
  const logins = useLogins();
  const [review, setReview] = useState<ImportReview>();
  const [choices, setChoices] = useState<CodeChoices>({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const pending = useRef<string>(undefined);
  const codes = scanner.scan?.codes ?? [];

  const captured = useRef(false);
  useEffect(() => {
    if (!autoCapture || captured.current || !service.qrCapture?.sources.includes(autoCapture)) return;
    captured.current = true;
    void scanner.capture(autoCapture);
  }, [autoCapture, scanner, service]);

  // A review left open holds parsed secrets in the vault's process: drop it on the way out.
  useEffect(
    () => () => {
      if (pending.current) void service.cancelImport(pending.current).catch(() => undefined);
    },
    [service],
  );

  async function run(action: () => Promise<void>) {
    setBusy(true);
    setError(undefined);
    try {
      await action();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  const start = () =>
    run(async () => {
      const links = new Blob([codes.map((code) => code.uri).join('\n')], { type: 'text/plain' });
      const next = await service.reviewImport('otpauth', links);
      pending.current = next.id;
      setReview(next);
      setChoices(initialChoices(next));
    });

  const finish = () =>
    run(async () => {
      const result = await service.finishImport(review!.id, codeLinks(choices));
      pending.current = undefined;
      toast({ message: t('otp.saved', { count: result.imported }), tone: 'success' });
      onClose();
    });

  function back() {
    if (pending.current) void service.cancelImport(pending.current).catch(() => undefined);
    pending.current = undefined;
    setReview(undefined);
  }

  const footer = review ? (
    <>
      <Button variant="secondary" disabled={busy} onClick={back}>
        {t('common.back')}
      </Button>
      <Button icon="check" busy={busy} onClick={() => void finish()}>
        {t('otp.saveCodes', { count: review.codes.length + review.otherItems })}
      </Button>
    </>
  ) : (
    <>
      <Button variant="secondary" disabled={busy} onClick={onClose}>
        {t('common.cancel')}
      </Button>
      <Button busy={busy} disabled={codes.length === 0 || scanner.busy} onClick={() => void start()}>
        {t('otp.continue')}
      </Button>
    </>
  );

  return (
    <Dialog
      open
      size="md"
      onClose={busy ? () => undefined : onClose}
      closeLabel={t('common.close')}
      title={review ? t('otp.reviewTitle') : (title ?? t('otp.scanTitle'))}
      description={review ? t('otp.reviewHelp') : (description ?? t('otp.scanHelp'))}
      footer={footer}
    >
      {review ? (
        logins ? (
          <>
            <ImportReviewList review={review} logins={logins} choices={choices} onChange={setChoices} />
            {review.warnings.length > 0 && (
              <Alert tone="warn">
                <ul className={styles.warnings}>
                  {review.warnings.map((warning, i) => (
                    <li key={i}>{warning}</li>
                  ))}
                </ul>
              </Alert>
            )}
          </>
        ) : (
          <Spinner size={20} />
        )
      ) : (
        <>
          <QrCapture scanner={scanner} />
          <MissingParts scanner={scanner} />
          {codes.length > 0 && (
            <div className={styles.found}>
              <p className={styles.legend}>{t('otp.found', { count: codes.length })}</p>
              <ul>
                {codes.map((code) => (
                  <li key={code.uri}>
                    <bdi>{codeLabel(code)}</bdi>
                    {code.counterBased && <small> · {t('otp.counterBasedShort')}</small>}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </>
      )}
      {error && <Alert>{error}</Alert>}
    </Dialog>
  );
}
