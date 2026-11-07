import type { Item, LoginDetails, QrCaptureSource, QrScan } from '@octapass/vault-client';
import { useCallback, useEffect, useRef, useState } from 'react';
import { useService } from '../../../app/ServiceContext';
import { t } from '../../../i18n';
import { errorMessage } from '../../../lib/errors';

export interface QrScanner {
  /** Everything scanned so far, summed up by the core. */
  scan: QrScan | undefined;
  busy: boolean;
  /** What went wrong with the last image or link, if anything. */
  notice: string | undefined;
  addImage(image: Blob): Promise<void>;
  /** Scanned or pasted text: an `otpauth://` link or a Google Authenticator export link. */
  addTexts(texts: string[]): Promise<void>;
  capture(source: QrCaptureSource): Promise<void>;
  reset(): void;
}

/**
 * Collects QR codes from images, the app's own sources and pasted links, and keeps the core's
 * summary of all of them, so the parts of a split Google Authenticator export add up.
 */
export function useQrScan(initialTexts: string[] = []): QrScanner {
  const service = useService();
  const texts = useRef<string[]>([]);
  const [scan, setScan] = useState<QrScan>();
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string>();

  const add = useCallback(
    async (read: () => Promise<string[] | undefined>) => {
      setBusy(true);
      setNotice(undefined);
      try {
        const found = await read();
        if (found === undefined) return;
        if (found.length === 0) {
          setNotice(t('otp.noneFound'));
          return;
        }
        texts.current = [...texts.current, ...found];
        const next = await service.summarizeQrScans(texts.current);
        setScan(next);
        const latest = await service.summarizeQrScans(found);
        if (latest.codes.length === 0) setNotice(latest.broken > 0 ? t('otp.broken') : t('otp.notCode', { count: latest.other }));
      } catch (error) {
        setNotice(errorMessage(error));
      } finally {
        setBusy(false);
      }
    },
    [service],
  );

  // Texts the screen opened with (the phone's camera scan) count as the first scan. Running twice
  // (React's strict mode) changes nothing: the summary counts each text once.
  const opening = useRef(initialTexts);
  useEffect(() => {
    if (opening.current.length > 0) void add(async () => opening.current);
  }, [add]);

  return {
    scan,
    busy,
    notice,
    addImage: (image) => add(() => service.readQrCodes(image)),
    addTexts: (found) => add(async () => found.map((text) => text.trim()).filter(Boolean)),
    capture: (source) => add(() => service.qrCapture!.capture(source)),
    reset: () => {
      texts.current = [];
      setScan(undefined);
      setNotice(undefined);
    },
  };
}

/** A login that only holds a one-time code: what an authenticator import or a scan makes. */
export function isCodeOnly(item: Item): boolean {
  if (item.overview.type !== 'login' && item.overview.type !== 'password') return false;
  const details = item.details as LoginDetails;
  return Boolean(details.totp) && !details.password && !item.overview.urls?.length && !details.passkeys?.length;
}

/** "GitHub (octo@example.com)", or whichever of the two there is. */
export function codeLabel(code: { issuer?: string; account?: string; title?: string }): string {
  const name = code.issuer || code.title;
  if (name && code.account) return `${name} (${code.account})`;
  return name || code.account || t('otp.untitled');
}
