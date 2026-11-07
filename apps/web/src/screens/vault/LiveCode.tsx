import { Button, Icon, Ring, useToast } from '@octapass/ui';
import { isHotp, loginDetails, type ItemSummary } from '@octapass/vault-client';
import { useEffect, useState } from 'react';
import { useService } from '../../app/ServiceContext';
import { t } from '../../i18n';
import { useCopy } from '../../lib/clipboard';
import { errorMessage } from '../../lib/errors';
import { formatCode, useTotp } from './Fields';
import styles from './LiveCode.module.css';

/**
 * A list row's current one-time code with its countdown, as a button that copies it. The item is
 * opened only for its code, the same way the detail view opens it, and again when it changes.
 */
export function LiveCode({ item }: { item: ItemSummary }) {
  const service = useService();
  const copy = useCopy();
  const [secret, setSecret] = useState<string>();
  const hotp = isHotp(secret);
  const code = useTotp(hotp ? undefined : secret);

  useEffect(() => {
    let live = true;
    service.getItem(item.id).then(
      (full) => live && setSecret(loginDetails(full)?.totp),
      () => undefined,
    );
    return () => {
      live = false;
    };
  }, [service, item.id, item.updatedAt]);

  if (hotp) return <NextCode item={item} />;
  if (code === 'invalid') return <span className={styles.invalid}>{t('list.codeInvalid')}</span>;
  return (
    <button
      type="button"
      className={styles.code}
      disabled={!code}
      aria-label={t('list.copyCode', { title: item.title || t('detail.untitled') })}
      title={t('copy.action', { what: t('fields.totpShort') })}
      onClick={() => code && void copy(code.code, t('fields.totp'))}
    >
      <span className={['mono', styles.digits].join(' ')} aria-hidden="true">
        {code ? formatCode(code.code) : '––– –––'}
      </span>
      {code && <Ring value={code.remaining / code.period} size={18} stroke={5} tone={code.remaining <= 5 ? 'warn' : 'free'} transition="linear" />}
      <Icon name="copy" size={15} className={styles.copy} />
    </button>
  );
}

/** A counter-based code has no "current" code to show: each press uses up one and copies it. */
function NextCode({ item }: { item: ItemSummary }) {
  const service = useService();
  const copy = useCopy();
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  if (!service.nextHotpCode) return null;
  return (
    <Button
      variant="ghost"
      size="sm"
      busy={busy}
      aria-label={t('list.nextCode', { title: item.title || t('detail.untitled') })}
      onClick={() => {
        setBusy(true);
        service
          .nextHotpCode!(item.id)
          .then(
            (next) => copy(next.code, t('fields.totp')),
            (e: unknown) => toast({ message: errorMessage(e), tone: 'danger' }),
          )
          .finally(() => setBusy(false));
      }}
    >
      {t('detail.hotpNext')}
    </Button>
  );
}
