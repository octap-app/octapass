import { Button, Icon, type IconName } from '@octapass/ui';
import type { ItemSummary, SessionState, UnlockMethods, VaultService } from '@octapass/vault-client';
import { t, type MessageKey } from '@octapass/web/src/i18n';
import { ItemAvatar } from '@octapass/web/src/lib/siteIcons';
import { useCallback, useEffect, useRef, useState, useSyncExternalStore, type KeyboardEvent } from 'react';
import { td } from '../i18n';
import styles from './QuickAccess.module.css';

export type CopyField = 'username' | 'password' | 'code';

/** What auto-type did: typed, or copied the password where nothing can type (Wayland without the portal). */
export type AutoTypeOutcome = { status: 'typed'; window?: string } | { status: 'copied'; clearsIn: number };

/** Why auto-type stopped, as the app reports it (`src-tauri/src/autotype.rs`). */
export interface AutoTypeFailure {
  code: string;
  window?: string;
  field?: 'username' | 'password' | 'totp';
  settingsUrl?: string;
}

/** The auto-type shortcut opened the window: the focused window, and the logins that belong to it. */
export interface AutoTypePicker {
  window?: string;
  matches: string[];
  /** Typing the only match was refused, and that login's title. */
  failure?: AutoTypeFailure;
  title?: string;
}

export interface QuickOpened {
  autoType?: AutoTypePicker;
}

/** What the window needs from the app besides the vault service. */
export interface QuickActions {
  /** Copies natively and returns the seconds until the clipboard clears. */
  copy(itemId: string, field: CopyField): Promise<number>;
  /** Types the login into the window quick access opened over. Rejects with an `AutoTypeFailure`. */
  autoType(itemId: string): Promise<AutoTypeOutcome>;
  openAccessibilitySettings(): void;
  hide(): void;
  openVault(): void;
  /** Subscribes to the window being shown again; returns the unsubscribe function. */
  onOpened(cb: (opened: QuickOpened) => void): () => void;
}

const MAX_ROWS = 50;
const FIELD_LABELS = { username: 'fields.username', password: 'fields.password', code: 'fields.totp' } as const satisfies Record<CopyField, MessageKey>;
const FIELD_ICONS: Record<CopyField, IconName> = { username: 'users', password: 'key', code: 'clock' };
const IS_MAC = typeof navigator !== 'undefined' && /Mac/.test(navigator.platform);

function fieldsFor(row: ItemSummary): CopyField[] {
  if (row.type === 'password') return ['password'];
  return row.hasTotp ? ['username', 'password', 'code'] : ['username', 'password'];
}

/** Enter copies the password, Shift+Enter the username, Option/Alt+Enter the one-time code. */
function fieldForKey(event: KeyboardEvent): CopyField {
  if (event.altKey) return 'code';
  return event.shiftKey ? 'username' : 'password';
}

/** ⌘↵ on a Mac, Ctrl+Enter elsewhere. */
function isTypeKey(event: KeyboardEvent): boolean {
  return IS_MAC ? event.metaKey : event.ctrlKey;
}

function failureMessage(failure: AutoTypeFailure, title: string): string {
  switch (failure.code) {
    case 'permissionRequired':
      return td('quick.autoType.permission');
    case 'screenLocked':
      return td('quick.autoType.screenLocked');
    case 'noWindow':
      return td('quick.autoType.noWindow');
    case 'ownWindow':
      return td('quick.autoType.ownWindow');
    case 'focusChanged':
      return td('quick.autoType.focusChanged', { window: failure.window ?? '' });
    case 'noMatch':
      return td('quick.autoType.noMatch', { window: failure.window ?? '', title });
    case 'keysHeld':
      return td('quick.autoType.keysHeld');
    case 'missingField':
      return td('quick.autoType.missingField', { title, what: td(`quick.fields.${failure.field === 'totp' ? 'code' : (failure.field ?? 'password')}`) });
    case 'invalidSequence':
      return td('quick.autoType.invalidSequence', { title });
    default:
      return td('quick.autoType.failed', { title });
  }
}

function useSession(service: VaultService): SessionState {
  const subscribe = useCallback((cb: () => void) => service.onSessionChange(cb), [service]);
  return useSyncExternalStore(subscribe, () => service.getSession());
}

/** Each opening, numbered so the search starts over even when the payload is the same. */
interface Opening {
  count: number;
  picker?: AutoTypePicker;
}

export function QuickAccess({ service, actions }: { service: VaultService; actions: QuickActions }) {
  const session = useSession(service);
  // Kept here, so a picker opened over a locked vault is still there after unlocking.
  const [opening, setOpening] = useState<Opening>({ count: 0 });
  useEffect(() => actions.onOpened((opened) => setOpening((last) => ({ count: last.count + 1, picker: opened?.autoType }))), [actions]);
  return (
    <main className={styles.window}>
      {session.status === 'unlocked' ? (
        <Search service={service} actions={actions} opening={opening} />
      ) : (
        <Locked service={service} actions={actions} signedOut={session.status === 'signedOut'} />
      )}
    </main>
  );
}

const JWT_COMMAND = /^(?:decode\s+jwt\s+)?(eyJ[\w-]+\.[\w-]+\.[\w-]*)$/i;

/** Tool commands typed in the search box (plan 16 §5): `uuid`, `uuid7`, `ulid`, `decode jwt <token>` or a pasted token. */
function useQuickTool(service: VaultService, query: string): { label: string; value: string } | undefined {
  const [result, setResult] = useState<{ query: string; label: string; value: string }>();
  useEffect(() => {
    const toolkit = service.toolkit;
    const text = query.trim();
    const command = text.toLowerCase();
    const token = JWT_COMMAND.exec(text)?.[1];
    let live = true;
    const show = (label: string, value: string) => live && setResult({ query, label, value });
    if (!toolkit) return;
    if (command === 'uuid' || command === 'uuid7') {
      void toolkit.run<{ values: string[] }>('random.uuid', { version: command === 'uuid7' ? 7 : 4 }).then(({ values }) => show('UUID', values[0]!));
    } else if (command === 'ulid') {
      void toolkit.run<{ values: string[] }>('random.ulid', {}).then(({ values }) => show('ULID', values[0]!));
    } else if (token) {
      void toolkit
        .run<{ payload?: unknown }>('jwt.decode', { token })
        .then(({ payload }) => show(t('tools.jwt.payload'), JSON.stringify(payload ?? null, null, 2)))
        .catch(() => undefined);
    }
    return () => {
      live = false;
    };
  }, [service, query]);
  return result?.query === query ? result : undefined;
}

function Search({ service, actions, opening }: { service: VaultService; actions: QuickActions; opening: Opening }) {
  const [query, setQuery] = useState('');
  const [rows, setRows] = useState<ItemSummary[]>([]);
  const [selected, setSelected] = useState(0);
  const [status, setStatus] = useState('');
  const [needsPermission, setNeedsPermission] = useState(false);
  const input = useRef<HTMLInputElement>(null);
  const picker = opening.picker;
  const tool = useQuickTool(service, query);

  useEffect(() => {
    let current = true;
    const load = () =>
      service
        .listItems({ query })
        .then((items) => {
          if (!current) return;
          let logins = items.filter((item) => item.type === 'login' || item.type === 'password');
          // The auto-type shortcut lists the logins for the window first, until a search.
          if (picker?.matches.length && !query) {
            const order = new Map(picker.matches.map((id, index) => [id, index]));
            logins = logins.filter((item) => order.has(item.id)).sort((a, b) => order.get(a.id)! - order.get(b.id)!);
          }
          setRows(logins.slice(0, MAX_ROWS));
          setSelected(0);
        })
        .catch(() => {});
    load();
    const stop = service.onItemsChange(load);
    return () => {
      current = false;
      stop();
    };
  }, [service, query, picker]);

  const showFailure = useCallback((failure: AutoTypeFailure, title: string) => {
    setNeedsPermission(failure.code === 'permissionRequired');
    setStatus(failureMessage(failure, title));
  }, []);

  useEffect(() => {
    if (opening.count === 0) return;
    setQuery('');
    setNeedsPermission(false);
    setStatus('');
    if (picker?.failure) showFailure(picker.failure, picker.title ?? '');
    input.current?.focus();
  }, [opening, picker, showFailure]);

  const copy = async (row: ItemSummary, field: CopyField) => {
    if (!fieldsFor(row).includes(field)) return;
    try {
      const clearsIn = await actions.copy(row.id, field);
      setStatus(td('quick.copied', { what: t(FIELD_LABELS[field]), title: row.title, count: clearsIn }));
    } catch {
      setStatus(td('quick.nothingToCopy', { what: td(`quick.fields.${field}`), title: row.title }));
    }
  };

  const type = async (row: ItemSummary) => {
    setNeedsPermission(false);
    setStatus(td('quick.autoType.typing', { title: row.title }));
    try {
      const outcome = await actions.autoType(row.id);
      setStatus(outcome.status === 'copied' ? td('quick.autoType.copied', { title: row.title, count: outcome.clearsIn }) : '');
    } catch (failure) {
      showFailure(failure as AutoTypeFailure, row.title);
    }
  };

  const onKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault();
      const step = event.key === 'ArrowDown' ? 1 : -1;
      setSelected((index) => Math.min(Math.max(index + step, 0), Math.max(rows.length - 1, 0)));
    } else if (event.key === 'Enter' && tool) {
      event.preventDefault();
      void navigator.clipboard.writeText(tool.value).then(() => setStatus(t('copy.copied', { what: tool.label })));
    } else if (event.key === 'Enter' && rows[selected]) {
      event.preventDefault();
      // Opened by the auto-type shortcut, plain Enter types too.
      if (isTypeKey(event) || (picker && !event.shiftKey && !event.altKey)) void type(rows[selected]);
      else void copy(rows[selected], fieldForKey(event));
    } else if (event.key === 'Escape') {
      actions.hide();
    }
  };

  const typeLabel = td('quick.autoType.action');
  return (
    <>
      <div className={styles.searchBar}>
        <Icon name={picker ? 'keyboard' : 'search'} size={20} />
        <input
          ref={input}
          className={styles.search}
          type="search"
          aria-label={td('quick.search')}
          aria-controls="quick-results"
          aria-activedescendant={rows[selected] ? `quick-${rows[selected].id}` : undefined}
          placeholder={td('quick.search')}
          autoFocus
          spellCheck={false}
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          onKeyDown={onKeyDown}
        />
      </div>
      {picker && (
        <p className={styles.picker}>
          {picker.window
            ? td(picker.matches.length ? 'quick.autoType.into' : 'quick.autoType.noLogin', { window: picker.window })
            : td('quick.autoType.pick')}
        </p>
      )}
      {tool && (
        <p className={styles.picker} dir="ltr" data-testid="quick-tool">
          {tool.value}
        </p>
      )}
      {rows.length === 0 ? (
        tool ? null : <p className={styles.empty}>{query ? td('quick.noMatch', { query }) : td('quick.empty')}</p>
      ) : (
        <ul id="quick-results" className={styles.results} role="listbox" aria-label={td('quick.results')}>
          {rows.map((row, index) => (
            <li
              key={row.id}
              id={`quick-${row.id}`}
              role="option"
              aria-selected={index === selected}
              className={index === selected ? styles.selected : styles.row}
              onMouseEnter={() => setSelected(index)}
            >
              <ItemAvatar name={row.title} urls={row.urls} size="sm" />
              <span className={styles.text}>
                <span className={styles.title}>
                  <bdi>{row.title}</bdi>
                </span>
                {row.subtitle && (
                  <span className={styles.subtitle}>
                    <bdi>{row.subtitle}</bdi>
                  </span>
                )}
              </span>
              <span className={styles.actions}>
                {fieldsFor(row).map((field) => (
                  <button key={field} type="button" className={styles.copy} title={t('copy.action', { what: td(`quick.fields.${field}`) })} onClick={() => void copy(row, field)}>
                    <Icon name={FIELD_ICONS[field]} size={16} label={t('copy.action', { what: td(`quick.fields.${field}`) })} />
                  </button>
                ))}
                <button type="button" className={styles.copy} title={typeLabel} onClick={() => void type(row)}>
                  <Icon name="keyboard" size={16} label={typeLabel} />
                </button>
              </span>
            </li>
          ))}
        </ul>
      )}
      <footer className={styles.footer}>
        <p role="status" className={styles.status}>
          {status}
          {needsPermission && (
            <button type="button" className={styles.link} onClick={actions.openAccessibilitySettings}>
              {td('quick.autoType.openSettings')}
            </button>
          )}
        </p>
        <p className={styles.keys} aria-hidden="true">
          {picker ? (
            <>
              <kbd>↵</kbd> {td('quick.keys.type')}
            </>
          ) : (
            <>
              <kbd>↵</kbd> {td('quick.keys.password')} <kbd>⇧↵</kbd> {td('quick.keys.username')} <kbd>⌥↵</kbd> {td('quick.keys.code')} <kbd>{IS_MAC ? '⌘↵' : 'Ctrl+↵'}</kbd> {td('quick.keys.type')}
            </>
          )}{' '}
          <kbd>esc</kbd> {td('quick.keys.close')}
        </p>
      </footer>
    </>
  );
}

function Locked({ service, actions, signedOut }: { service: VaultService; actions: QuickActions; signedOut: boolean }) {
  const [methods, setMethods] = useState<UnlockMethods>();
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!signedOut) service.getUnlockMethods().then(setMethods, () => {});
  }, [service, signedOut]);

  const unlock = async () => {
    setBusy(true);
    setError('');
    try {
      await service.unlockWithDevice();
    } catch {
      setError(td('quick.unlockFailed'));
    } finally {
      setBusy(false);
    }
  };

  const canUnlock = methods?.deviceUnlockEnabled && !methods.passwordRequired;
  return (
    <section className={styles.locked}>
      <Icon name="lock" size={28} />
      <h1 className={styles.heading}>{signedOut ? td('quick.signedOut') : td('quick.locked')}</h1>
      {error && <p className={styles.error}>{error}</p>}
      <div className={styles.buttons}>
        {canUnlock && (
          <Button icon="fingerprint" busy={busy} onClick={() => void unlock()}>
            {t('lock.unlockWith', { method: methods.label })}
          </Button>
        )}
        <Button variant={canUnlock ? 'secondary' : 'primary'} onClick={actions.openVault}>
          {td('quick.openApp')}
        </Button>
      </div>
    </section>
  );
}
