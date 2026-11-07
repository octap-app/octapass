import { Button, IconButton, Ring, TextField, useToast } from '@octapass/ui';
import { hotpCounter, isHotp, type HotpCode, type TotpCode } from '@octapass/vault-client';
import { useEffect, useState, type ReactNode } from 'react';
import { useService } from '../../app/ServiceContext';
import { t } from '../../i18n';
import { useCopy } from '../../lib/clipboard';
import { errorMessage } from '../../lib/errors';
import { useConfirmReveal } from '../../lib/identityGate';
import styles from './Fields.module.css';

export function FieldList({ title, children }: { title?: string; children: ReactNode }) {
  return (
    <section className={styles.group}>
      {title && <h2 className={styles.groupTitle}>{title}</h2>}
      <dl className={styles.list}>{children}</dl>
    </section>
  );
}

export function CopyButton({ value, what, secret = true, gated = false }: { value: string; what: string; secret?: boolean; gated?: boolean }) {
  const copy = useCopy();
  const confirm = useConfirmReveal();
  async function run() {
    if (gated && !(await confirm({ reason: t('identityGate.body') }))) return;
    await copy(value, what, { secret });
  }
  return <IconButton size="sm" icon="copy" label={t('copy.action', { what })} onClick={() => void run()} />;
}

export interface FieldProps {
  label: string;
  value?: string;
  /** Copy button label noun, defaults to the label. */
  what?: string;
  mono?: boolean;
  copy?: boolean;
  /** Non-secret copies (usernames, URLs) aren't cleared from the clipboard. */
  secret?: boolean;
  multiline?: boolean;
  /** An address or number that reads left to right in every language. */
  ltr?: boolean;
  children?: ReactNode;
  actions?: ReactNode;
}

export function Field({ label, value, what, mono, copy = true, secret = false, multiline, ltr, children, actions }: FieldProps) {
  if (!value && !children) return null;
  return (
    <div className={styles.field}>
      <dt className={styles.label}>{label}</dt>
      {/* What people typed keeps its own direction (bdi), so "Wi-Fi (5G)" stays whole in Arabic. */}
      <dd className={[styles.value, mono && 'mono', multiline && styles.multiline].filter(Boolean).join(' ')}>{children ?? <bdi dir={ltr ? 'ltr' : undefined}>{value}</bdi>}</dd>
      <div className={styles.actions}>
        {actions}
        {copy && value && <CopyButton value={value} what={what ?? label} secret={secret} gated={secret} />}
      </div>
    </div>
  );
}

/** A secret shown as dots until revealed. Revealing is per field and resets when the item changes. */
export function SecretField({ label, value, what, format = (v) => v }: { label: string; value?: string; what?: string; format?: (value: string) => string }) {
  const [revealed, setRevealed] = useState(false);
  const confirm = useConfirmReveal();
  if (!value) return null;
  async function toggle() {
    if (!revealed && !(await confirm({ reason: t('identityGate.body') }))) return;
    setRevealed((r) => !r);
  }
  return (
    <Field
      label={label}
      value={value}
      what={what}
      secret
      mono
      actions={
        <IconButton size="sm" icon={revealed ? 'eyeOff' : 'eye'} label={revealed ? t('common.hideWhat', { what: what ?? label }) : t('common.revealWhat', { what: what ?? label })} aria-pressed={revealed} onClick={() => void toggle()} />
      }
    >
      {revealed ? <span className={styles.revealed}>{format(value)}</span> : <span aria-label={t('detail.hiddenValue')}>{'•'.repeat(Math.min(16, Math.max(8, value.length)))}</span>}
    </Field>
  );
}

/** Calls the service every second, aligned to the clock, so the code flips exactly on the period boundary. */
export function useTotp(secret: string | undefined): TotpCode | 'invalid' | undefined {
  const service = useService();
  const [code, setCode] = useState<TotpCode | 'invalid'>();

  useEffect(() => {
    if (!secret) return;
    let timer: ReturnType<typeof setTimeout>;
    let cancelled = false;
    const tick = () => {
      service.totpCode(secret).then(
        (next) => !cancelled && setCode(next),
        () => !cancelled && setCode('invalid'),
      );
      timer = setTimeout(tick, 1000 - (Date.now() % 1000));
    };
    tick();
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [service, secret]);

  return secret ? code : undefined;
}

export function formatCode(code: string): string {
  const half = Math.ceil(code.length / 2);
  return `${code.slice(0, half)} ${code.slice(half)}`;
}

/**
 * A counter-based code. Each code exists once: asking saves the moved counter first, then shows it.
 * Only the code asked for here is shown, and only until the item is left.
 */
function HotpField({ itemId, secret }: { itemId?: string; secret: string }) {
  const service = useService();
  const toast = useToast();
  const [code, setCode] = useState<HotpCode>();
  const [busy, setBusy] = useState(false);
  const [counter, setCounter] = useState<string>();
  const next = hotpCounter(secret);

  async function run(action: () => Promise<void>) {
    setBusy(true);
    try {
      await action();
    } catch (e) {
      toast({ message: errorMessage(e), tone: 'danger' });
    } finally {
      setBusy(false);
    }
  }
  // A shared snapshot or an old version can't move anything: it only says what kind of code this is.
  const usable = Boolean(itemId && service.nextHotpCode);
  const valid = counter !== undefined && /^\d{1,15}$/.test(counter);
  return (
    <Field label={t('fields.totp')} value={code?.code} what={t('fields.totpShort')} secret copy={Boolean(code)}>
      <span className={styles.totp}>
        <span className={['mono', styles.code].join(' ')} aria-live="polite">
          {code ? formatCode(code.code) : '––– –––'}
        </span>
        {usable && (
          <Button variant="secondary" size="sm" busy={busy} onClick={() => void run(async () => setCode(await service.nextHotpCode!(itemId!)))}>
            {t('detail.hotpNext')}
          </Button>
        )}
        <span className={styles.remaining}>{t('detail.hotpCounter', { counter: next })}</span>
        {usable && service.setHotpCounter && counter === undefined && (
          <Button variant="ghost" size="sm" onClick={() => setCounter(String(next))}>
            {t('detail.hotpResync')}
          </Button>
        )}
      </span>
      {counter !== undefined && (
        <span className={styles.totpCounter}>
          <TextField label={t('detail.hotpCounterField')} mono inputMode="numeric" value={counter} onChange={(e) => setCounter(e.target.value)} hint={t('detail.hotpCounterHint')} error={valid ? undefined : t('detail.hotpCounterInvalid')} />
          <Button
            size="sm"
            disabled={!valid}
            busy={busy}
            onClick={() =>
              void run(async () => {
                await service.setHotpCounter!(itemId!, Number(counter));
                setCode(undefined);
                setCounter(undefined);
              })
            }
          >
            {t('common.save')}
          </Button>
          <Button variant="ghost" size="sm" onClick={() => setCounter(undefined)}>
            {t('common.cancel')}
          </Button>
        </span>
      )}
    </Field>
  );
}

/** `itemId`: the live item a counter-based code belongs to. Left out where nothing can be saved. */
export function TotpField({ secret, itemId }: { secret?: string; itemId?: string }) {
  if (secret && isHotp(secret)) return <HotpField secret={secret} itemId={itemId} />;
  return <TimeCodeField secret={secret} />;
}

function TimeCodeField({ secret }: { secret?: string }) {
  const code = useTotp(secret);
  if (!secret) return null;
  if (code === 'invalid') {
    return <Field label={t('fields.totp')} value={t('detail.totpInvalid')} copy={false} />;
  }
  return (
    <Field label={t('fields.totp')} value={code?.code} what={t('fields.totpShort')} secret>
      <span className={styles.totp}>
        <span className={['mono', styles.code].join(' ')} aria-live="off">
          {code ? formatCode(code.code) : '––– –––'}
        </span>
        {code && (
          <>
            <Ring value={code.remaining / code.period} size={22} stroke={5} tone={code.remaining <= 5 ? 'warn' : 'free'} transition="linear" />
            <span className={styles.remaining}>{t('detail.totpRemaining', { count: code.remaining })}</span>
          </>
        )}
      </span>
    </Field>
  );
}
