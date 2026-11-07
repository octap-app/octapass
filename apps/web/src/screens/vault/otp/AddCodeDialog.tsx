import { Button, Dialog, useToast } from '@octapass/ui';
import { isHotp, type Item, type LoginDetails } from '@octapass/vault-client';
import { useEffect, useState } from 'react';
import { useService } from '../../../app/ServiceContext';
import { Alert } from '../../../components/Alert';
import { t } from '../../../i18n';
import { errorMessage } from '../../../lib/errors';
import { MissingParts, QrCapture } from './QrCapture';
import { codeLabel, useQrScan } from './useQrScan';
import styles from './otp.module.css';

/** Item → Add one-time code: from a QR code, an image, or the setup link or key. */
export function AddCodeDialog({ item, open, onClose }: { item: Item; open: boolean; onClose: () => void }) {
  return open ? <AddCode item={item} onClose={onClose} /> : null;
}

function AddCode({ item, onClose }: { item: Item; onClose: () => void }) {
  const service = useService();
  const toast = useToast();
  const scanner = useQrScan();
  const [chosen, setChosen] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const codes = scanner.scan?.codes ?? [];

  // The code whose issuer is this login's name, else the first one.
  useEffect(() => {
    if (codes.length === 0 || codes.some((code) => code.uri === chosen)) return;
    const title = item.overview.title.toLowerCase();
    setChosen((codes.find((code) => code.issuer && title.includes(code.issuer.toLowerCase())) ?? codes[0])?.uri);
  }, [codes, chosen, item.overview.title]);

  async function save(totp: string) {
    setBusy(true);
    setError(undefined);
    try {
      await service.saveItem({ ...item, details: { ...(item.details as LoginDetails), totp } });
      toast({ message: t('otp.added'), tone: 'success' });
      onClose();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  // A bare key: saved as it is once the core can compute a code from it.
  async function saveSecret(secret: string) {
    try {
      if (!isHotp(secret)) await service.totpCode(secret);
    } catch {
      setError(t('otp.invalidLink'));
      return;
    }
    await save(secret.replace(/\s/g, ''));
  }

  return (
    <Dialog
      open
      size="md"
      onClose={busy ? () => undefined : onClose}
      closeLabel={t('common.close')}
      title={t('otp.addCode')}
      description={t('otp.addCodeHelp')}
      footer={
        <>
          <Button variant="secondary" disabled={busy} onClick={onClose}>
            {t('common.cancel')}
          </Button>
          <Button icon="plus" busy={busy} disabled={!chosen} onClick={() => chosen && void save(chosen)}>
            {t('otp.save')}
          </Button>
        </>
      }
    >
      <QrCapture scanner={scanner} onSecret={saveSecret} />
      <MissingParts scanner={scanner} />
      {codes.length > 0 && (
        <fieldset className={styles.options}>
          <legend className={styles.legend}>{codes.length > 1 ? t('otp.chooseOne') : t('otp.foundOne')}</legend>
          {codes.map((code) => (
            <label key={code.uri} className={styles.option}>
              <input type="radio" name="scanned-code" checked={chosen === code.uri} onChange={() => setChosen(code.uri)} />
              <span className={styles.optionText}>
                <strong>
                  <bdi>{codeLabel(code)}</bdi>
                </strong>
                {code.counterBased && <small>{t('otp.counterBased')}</small>}
              </span>
            </label>
          ))}
        </fieldset>
      )}
      {error && <Alert>{error}</Alert>}
    </Dialog>
  );
}
