import { Spinner } from '@octapass/ui';
import { ScanCodesDialog } from '@octapass/web/src/screens/vault/otp/ScanCodesDialog';
import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router';
import { useExtension } from './ExtensionContext';

/**
 * One-time codes from QR codes: what the image menu read on a page, or else a screenshot of the
 * page in the current tab, taken right away.
 */
export function ScanScreen() {
  const { api } = useExtension();
  const navigate = useNavigate();
  const [texts, setTexts] = useState<string[]>();
  const taken = useRef(false);

  useEffect(() => {
    if (taken.current) return;
    taken.current = true;
    void api.takeImageScan().then(
      (found) => setTexts(found ?? []),
      () => setTexts([]),
    );
  }, [api]);

  if (!texts) return <Spinner size={22} />;
  return <ScanCodesDialog open initialTexts={texts} {...(texts.length === 0 ? { autoCapture: 'page' as const } : {})} onClose={() => navigate('/items/site')} />;
}
