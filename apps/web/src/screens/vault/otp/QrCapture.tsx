import { Button, Icon, TextField, type IconName } from '@octapass/ui';
import type { QrCaptureSource } from '@octapass/vault-client';
import { useEffect, useId, useRef, useState, type DragEvent, type FormEvent } from 'react';
import { useService } from '../../../app/ServiceContext';
import { t } from '../../../i18n';
import type { QrScanner } from './useQrScan';
import styles from './otp.module.css';

const SOURCE_ICONS: Record<QrCaptureSource, IconName> = { page: 'qrCode', screen: 'monitor', camera: 'camera', photo: 'image' };

export interface QrCaptureProps {
  scanner: QrScanner;
  /** A pasted bare secret (no `otpauth://`): only a login's own code takes one. Without it, only links. */
  onSecret?: (secret: string) => Promise<void>;
}

/**
 * Every way to bring in a QR code: the app's own sources (this page, part of the screen, the
 * camera, a photo), an image file chosen, dropped or pasted, or the setup link itself.
 */
export function QrCapture({ scanner, onSecret }: QrCaptureProps) {
  const service = useService();
  const sources = service.qrCapture?.sources ?? [];
  const chooseFiles = service.qrCapture?.chooseFiles ?? true;
  const input = useRef<HTMLInputElement>(null);
  const linkId = useId();
  const [link, setLink] = useState('');
  const [dragging, setDragging] = useState(false);

  // A screenshot pasted anywhere while this is open. Text pasted into a field stays there.
  useEffect(() => {
    const onPaste = (event: ClipboardEvent) => {
      const image = [...(event.clipboardData?.files ?? [])].find((file) => file.type.startsWith('image/'));
      if (image) {
        event.preventDefault();
        void scanner.addImage(image);
        return;
      }
      const target = event.target as HTMLElement | null;
      if (target?.closest('input, textarea')) return;
      const text = event.clipboardData?.getData('text/plain').trim();
      if (text && /^otpauth/i.test(text)) {
        event.preventDefault();
        void scanner.addTexts([text]);
      }
    };
    document.addEventListener('paste', onPaste);
    return () => document.removeEventListener('paste', onPaste);
  }, [scanner]);

  function onDrop(event: DragEvent) {
    event.preventDefault();
    setDragging(false);
    const image = [...event.dataTransfer.files].find((file) => file.type.startsWith('image/'));
    if (image) void scanner.addImage(image);
  }

  async function submitLink(event: FormEvent) {
    event.preventDefault();
    const text = link.trim();
    if (!text) return;
    if (!/^otpauth/i.test(text) && onSecret) await onSecret(text);
    else await scanner.addTexts([text]);
    setLink('');
  }

  return (
    <div className={styles.capture}>
      {sources.length > 0 && (
        <div className={styles.sources}>
          {sources.map((source) => (
            <Button key={source} variant="secondary" icon={SOURCE_ICONS[source]} disabled={scanner.busy} onClick={() => void scanner.capture(source)}>
              {t(`otp.source.${source}`)}
            </Button>
          ))}
        </div>
      )}
      <div
        className={styles.drop}
        data-dragging={dragging || undefined}
        onDragOver={(event) => {
          event.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
      >
        <Icon name="image" size={22} />
        {chooseFiles && (
          <Button variant="secondary" size="sm" disabled={scanner.busy} onClick={() => input.current?.click()}>
            {t('otp.chooseImage')}
          </Button>
        )}
        <p>{chooseFiles ? t('otp.dropOrPaste') : t('otp.pasteImage')}</p>
        <input
          ref={input}
          type="file"
          accept="image/png,image/jpeg,image/webp,image/gif"
          hidden
          onChange={(event) => {
            const file = event.target.files?.[0];
            event.target.value = '';
            if (file) void scanner.addImage(file);
          }}
        />
      </div>
      <form className={styles.link} onSubmit={(event) => void submitLink(event)}>
        <TextField
          id={linkId}
          label={t(onSecret ? 'otp.pasteLinkOrKey' : 'otp.pasteLink')}
          hint={t(onSecret ? 'otp.pasteLinkOrKeyHint' : 'otp.pasteLinkHint')}
          autoComplete="off"
          spellCheck={false}
          mono
          value={link}
          onChange={(event) => setLink(event.target.value)}
        />
        <Button type="submit" variant="secondary" disabled={scanner.busy || !link.trim()}>
          {t('otp.addLink')}
        </Button>
      </form>
      <p className={styles.status} role="status">
        {scanner.busy ? t('otp.reading') : scanner.notice}
      </p>
    </div>
  );
}

/** "2 of 3 QR codes scanned" for each Google Authenticator export still missing parts. */
export function MissingParts({ scanner }: { scanner: QrScanner }) {
  const incomplete = scanner.scan?.incomplete ?? [];
  if (incomplete.length === 0) return null;
  return (
    <ul className={styles.missing}>
      {incomplete.map((batch) => (
        <li key={batch.id}>
          <Icon name="info" size={16} />
          {t('otp.batch', { scanned: batch.scanned.length, size: batch.size })}
        </li>
      ))}
    </ul>
  );
}
