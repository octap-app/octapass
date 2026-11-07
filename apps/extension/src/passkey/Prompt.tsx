import type { PasskeyMatch } from '@octapass/core';
import { Avatar, Button, Icon, IconButton, Logo, Spinner, TextField, type IconName } from '@octapass/ui';
import { isVaultError } from '@octapass/vault-client';
import { useEffect, useId, useLayoutEffect, useRef, useState, useSyncExternalStore, type FormEvent, type KeyboardEvent, type ReactNode } from 'react';
import { tx } from '../i18n';
import type { PasskeyPrompt } from '../shared/passkey';
import type { PasskeyClient } from './client';
import type { FrameLink } from './frame';
import styles from './Prompt.module.css';

/**
 * The web vault's messages for vault errors, loaded only when one needs showing: its catalog is most
 * of what the prompt would otherwise load.
 */
async function describe(error: unknown): Promise<string> {
  const { errorMessage } = await import('@octapass/web/src/lib/errors');
  return errorMessage(error);
}

interface PromptProps {
  client: PasskeyClient;
  requestId: string;
  /** The content script framing us, for sizing the frame. Missing in tests and when opened as a tab. */
  frame?: FrameLink | undefined;
}

/** The Octa Pass passkey prompt, framed by the website that asked. */
export function Prompt({ client, requestId, frame }: PromptProps) {
  const status = useSyncExternalStore(client.onStatus, client.status);
  const [prompt, setPrompt] = useState<PasskeyPrompt | 'ended'>();
  const [busy, setBusy] = useState<string | boolean>(false);
  const [error, setError] = useState<string>();

  useEffect(() => {
    client.prompt(requestId).then(setPrompt, () => setPrompt('ended'));
  }, [client, requestId]);

  /** `key`: which control is busy (a passkey's id, or true for the whole prompt). */
  async function run(action: () => Promise<void>, key: string | true = true) {
    setBusy(key);
    setError(undefined);
    try {
      await action();
    } catch (e) {
      setError(await describe(e));
      setBusy(false);
    }
  }

  // The service worker forgot the request (it ended, or the worker restarted): only the content
  // script can take the prompt away.
  const cancel = () => void run(() => client.cancel(requestId).catch(() => frame?.close()));
  const footer = (
    <>
      <Button variant="ghost" size="sm" disabled={!!busy} onClick={() => void run(() => client.fallback(requestId))}>
        {tx('passkey.another')}
      </Button>
      <Button variant="secondary" size="sm" disabled={!!busy} onClick={cancel}>
        {tx('passkey.cancel')}
      </Button>
    </>
  );

  if (!prompt || (prompt !== 'ended' && !status)) return skeleton(frame, cancel);
  if (prompt === 'ended') {
    return (
      <Frame frame={frame} onClose={() => frame?.close()} footer={<Button variant="secondary" size="sm" onClick={() => frame?.close()}>{tx('passkey.close')}</Button>}>
        <Message icon="clock">{tx('passkey.ended')}</Message>
      </Frame>
    );
  }

  // The title always names the real site (rpId, checked against the origin). `rp.name` is chosen by
  // the page, so a look-alike could claim to be anyone.
  const title = prompt.kind === 'create' ? tx('passkey.createTitle', { site: prompt.rpId }) : tx('passkey.getTitle', { site: prompt.rpId });
  const frameProps = { frame, title, onClose: busy ? undefined : cancel, footer };

  if (status === 'signedOut') {
    return (
      <Frame {...frameProps}>
        <Message icon="passkey">{tx('passkey.signedOut')}</Message>
      </Frame>
    );
  }
  if (status === 'locked') {
    return (
      <Frame {...frameProps}>
        <Unlock client={client} />
      </Frame>
    );
  }

  return (
    <Frame {...frameProps}>
      {error && (
        <p className={styles.error} role="alert">
          <Icon name="alert" size={16} />
          {error}
        </p>
      )}
      {prompt.kind === 'create' ? (
        <div className={styles.create}>
          {prompt.userName && (
            <div className={styles.account}>
              <Avatar name={prompt.userName} />
              <span className={styles.who}>
                <strong dir="auto">{prompt.userName}</strong>
                <small dir="auto">{prompt.rpId}</small>
              </span>
            </div>
          )}
          <p className={styles.body}>{tx('passkey.createBody', { user: prompt.userName ?? '' })}</p>
          <Button block icon="passkey" busy={busy === true} disabled={!!busy} autoFocus onClick={() => void run(() => client.approve(requestId))}>
            {tx('passkey.save')}
          </Button>
        </div>
      ) : (
        <Matches client={client} requestId={requestId} prompt={prompt} busy={busy} onPick={(match) => void run(() => client.approve(requestId, match), match.credentialId)} />
      )}
    </Frame>
  );
}

function Matches({ client, requestId, prompt, busy, onPick }: { client: PasskeyClient; requestId: string; prompt: PasskeyPrompt; busy: string | boolean; onPick: (match: PasskeyMatch) => void }) {
  const [matches, setMatches] = useState<{ list: PasskeyMatch[]; titles: Map<string, string> }>();
  const list = useRef<HTMLUListElement>(null);

  useEffect(() => {
    // The logins' titles are a nicety: the list doesn't wait for them to fail.
    const titles = client.titles(prompt.origin).catch(() => new Map<string, string>());
    client.matches(requestId).then(
      async (found) => setMatches({ list: found, titles: found.length ? await titles : new Map() }),
      () => setMatches({ list: [], titles: new Map() }),
    );
  }, [client, requestId, prompt.origin]);

  // Ready to pick with Enter, or to move with the arrows.
  useEffect(() => {
    list.current?.querySelector('button')?.focus();
  }, [matches]);

  if (!matches) return <SkeletonRows />;
  if (!matches.list.length) return <Message icon="passkey">{tx('passkey.noPasskeys', { site: prompt.rpId })}</Message>;

  function onKeyDown(event: KeyboardEvent<HTMLUListElement>) {
    const buttons = [...(list.current?.querySelectorAll('button') ?? [])];
    const at = buttons.indexOf(document.activeElement as HTMLButtonElement);
    const to = { ArrowDown: at + 1, ArrowUp: at - 1, Home: 0, End: buttons.length - 1 }[event.key];
    if (to === undefined) return;
    event.preventDefault();
    buttons[(to + buttons.length) % buttons.length]?.focus();
  }

  return (
    <>
      <p className={styles.body}>{tx('passkey.getBody')}</p>
      <ul ref={list} className={styles.matches} aria-label={tx('passkey.getBody')} onKeyDown={onKeyDown}>
        {matches.list.map((match) => {
          const name = match.userDisplayName || match.userName;
          const title = matches.titles.get(match.itemId);
          const detail = [name !== match.userName && match.userName, title && title !== name && title !== match.userName && title].filter(Boolean).join(' · ');
          const picked = busy === match.credentialId;
          return (
            <li key={match.credentialId}>
              <button type="button" className={styles.match} disabled={!!busy} aria-busy={picked || undefined} data-picked={picked || undefined} onClick={() => onPick(match)}>
                <Avatar name={name} />
                <span className={styles.who}>
                  <strong dir="auto">{name}</strong>
                  {detail && <small dir="auto">{detail}</small>}
                </span>
                <span className={styles.go} aria-hidden="true">
                  {picked ? <Spinner size={18} /> : <Icon name="chevronRight" size={18} />}
                </span>
              </button>
            </li>
          );
        })}
      </ul>
    </>
  );
}

function Unlock({ client }: { client: PasskeyClient }) {
  const [password, setPassword] = useState('');
  const [revealed, setRevealed] = useState(false);
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!password) return setError(tx('passkey.passwordRequired'));
    setBusy(true);
    setError(undefined);
    try {
      await client.unlock(password);
    } catch (e) {
      setError(isVaultError(e) ? await describe(e) : String(e));
      setPassword('');
      setBusy(false);
    }
  }

  return (
    <form className={styles.form} onSubmit={submit} noValidate>
      <p className={styles.body}>{tx('passkey.lockedBody')}</p>
      <TextField
        label={tx('passkey.masterPassword')}
        type={revealed ? 'text' : 'password'}
        mono={revealed}
        dir="ltr"
        spellCheck={false}
        autoCapitalize="off"
        autoCorrect="off"
        autoComplete="current-password"
        autoFocus
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        error={error}
        actions={<IconButton size="sm" icon={revealed ? 'eyeOff' : 'eye'} label={tx(revealed ? 'passkey.hidePassword' : 'passkey.showPassword')} aria-pressed={revealed} onClick={() => setRevealed((r) => !r)} />}
      />
      <Button type="submit" block busy={busy} icon="lock">
        {tx('passkey.unlock')}
      </Button>
    </form>
  );
}

function Message({ icon, children }: { icon: IconName; children: ReactNode }) {
  return (
    <div className={styles.message}>
      <span className={styles.messageIcon}>
        <Icon name={icon} size={22} />
      </span>
      <p>{children}</p>
    </div>
  );
}

function SkeletonRows() {
  return (
    <div className={styles.skeletonRows} aria-hidden="true">
      {[0, 1].map((i) => (
        <div key={i} className={styles.skeletonRow}>
          <span className={styles.skeletonAvatar} />
          <span className={styles.skeletonLines}>
            <span className={styles.skeletonLine} />
            <span className={styles.skeletonLine} />
          </span>
        </div>
      ))}
    </div>
  );
}

/**
 * Shown before the service worker has answered: the prompt's shape, so nothing jumps. A plain
 * function, not a component, so the frame stays mounted (and doesn't replay its entrance) when the
 * real content arrives.
 */
function skeleton(frame: FrameLink | undefined, onClose: () => void) {
  const pills = (
    <>
      <span className={styles.skeletonPill} />
      <span className={styles.skeletonPill} />
    </>
  );
  return (
    <Frame frame={frame} title={<span className={styles.skeletonTitle} />} onClose={onClose} footer={pills} busy>
      <SkeletonRows />
    </Frame>
  );
}

/** Tells the content script how tall the prompt's content is, so the frame fits it. */
function useReportHeight(frame: FrameLink | undefined) {
  const main = useRef<HTMLElement>(null);
  const scroll = useRef<HTMLDivElement>(null);
  const content = useRef<HTMLDivElement>(null);
  useLayoutEffect(() => {
    if (!frame || !main.current || !scroll.current || !content.current || typeof ResizeObserver === 'undefined') return;
    const [m, s, c] = [main.current, scroll.current, content.current];
    // The content's own height, not the frame's: inside a frame that's too short, the list scrolls.
    const report = () => frame.height(Math.ceil(m.getBoundingClientRect().height - s.clientHeight + c.getBoundingClientRect().height));
    const observer = new ResizeObserver(report);
    observer.observe(m);
    observer.observe(c);
    report();
    return () => observer.disconnect();
  }, [frame]);
  return { main, scroll, content };
}

export function Frame({ frame, title, onClose, footer, busy, children }: { frame?: FrameLink | undefined; title?: ReactNode; onClose?: (() => void) | undefined; footer?: ReactNode; busy?: boolean; children?: ReactNode }) {
  const { main, scroll, content } = useReportHeight(frame);
  const titleId = useId();

  useEffect(() => {
    if (!onClose) return;
    const onKey = (event: globalThis.KeyboardEvent) => {
      if (event.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  return (
    <main ref={main} className={styles.frame} aria-labelledby={title ? titleId : undefined} aria-busy={busy || undefined}>
      <header className={styles.head}>
        <Logo variant="tile" size={28} />
        <div className={styles.heading}>
          <span className={styles.brand}>Octa Pass</span>
          {title && (
            <h1 id={titleId} className={styles.title}>
              {title}
            </h1>
          )}
        </div>
        {onClose && <IconButton icon="close" size="sm" label={tx('passkey.cancel')} className={styles.close} onClick={onClose} />}
      </header>
      <div ref={scroll} className={styles.scroll}>
        <div ref={content} className={styles.content}>
          {busy && <span className="visually-hidden">{tx('passkey.working')}</span>}
          {children}
        </div>
      </div>
      {footer && <footer className={styles.foot}>{footer}</footer>}
    </main>
  );
}
