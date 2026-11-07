import { Button, EmptyState, Icon, IconButton, Logo } from '@octapass/ui';
import { loginDetails, wifiSsid, type ItemSummary, type ItemType, type Vault } from '@octapass/vault-client';
import { useDeferredValue, useMemo, useRef, useState, type KeyboardEvent } from 'react';
import { NavLink, Outlet, useMatch, useNavigate, useOutletContext, useParams } from 'react-router';
import { useService } from '../../app/ServiceContext';
import { Alert } from '../../components/Alert';
import { Menu } from '../../components/Menu';
import { SortMenu } from '../../components/SortMenu';
import { t, type MessageKey } from '../../i18n';
import { useCopy } from '../../lib/clipboard';
import { groupingsFor, useCombineSites, useListArrangement } from '../../lib/listArrangement';
import { parseScope, ITEM_TYPES, type Scope } from '../../lib/scope';
import { ItemAvatar } from '../../lib/siteIcons';
import { ItemUseProvider, useScopeItems, useUsageTracker } from '../../lib/usage';
import { useVaults } from '../../lib/useItems';
import { useShortcuts } from '../../lib/useShortcuts';
import { useWifiRadar, type WifiRadarState } from '../../lib/wifi';
import { stageLabel } from './Environment';
import { IN_RANGE_SECTION, ItemSections, useSections } from './ItemSections';
import { LiveCode } from './LiveCode';
import { ScanCodesDialog } from './otp/ScanCodesDialog';
import { TYPE_ICONS } from './Sidebar';
import type { LayoutContext } from './VaultLayout';
import { nearbyFirst, WifiListTools, WifiMark, WifiPermissionNote } from './Wifi';
import styles from './ItemsPage.module.css';

const TRASH_DAYS = 30;
// The rows the arrow keys move between: items, and the rows for a website's logins.
const ROW_SELECTOR = 'a[data-item-id], button[data-site]';

export function scopeTitle(scope: Scope, vaults: Vault[] | undefined): string {
  switch (scope.kind) {
    case 'vault':
      return vaults?.find((v) => v.id === scope.vaultId)?.name ?? t('scopes.vault');
    case 'type':
      return t(`categories.${scope.type}` as MessageKey);
    case 'smart':
      return t(`scopes.${scope.list}` as MessageKey);
    default:
      return t(`scopes.${scope.kind}` as MessageKey);
  }
}

function daysLeft(deletedAt: string): number {
  return Math.max(0, Math.ceil(TRASH_DAYS - (Date.now() - Date.parse(deletedAt)) / 86_400_000));
}

/** Certificates and keys are made in the Tools section, not typed into the editor. */
const TOOL_MADE: ReadonlySet<ItemType> = new Set(['certificate', 'key']);

export function ItemsPage() {
  const params = useParams();
  const scope = parseScope(params.scope);
  const scopeKey = params.scope ?? 'all';
  const { openDrawer } = useOutletContext<LayoutContext>();
  const navigate = useNavigate();
  const service = useService();
  const copy = useCopy();
  const usage = useUsageTracker();
  const vaults = useVaults();
  const [query, setQuery] = useState('');
  const [scanning, setScanning] = useState(false);
  const [projectFilter, setProjectFilter] = useState('');
  const [stageFilter, setStageFilter] = useState('');
  const deferredQuery = useDeferredValue(query.trim());
  const { items, error, retry } = useScopeItems(scope, deferredQuery || undefined);
  const searchRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const showingList = useMatch('/items/:scope') !== null;
  const title = scopeTitle(scope, vaults);
  const isTrash = scope.kind === 'trash';
  // Recently created, Frequently used, Recently used and Recently modified keep their own order.
  const isSmart = scope.kind === 'smart';
  const vault = scope.kind === 'vault' ? vaults?.find((v) => v.id === scope.vaultId) : undefined;
  const canAdd = !isTrash && vault?.role !== 'read' && !vault?.untrusted;
  // Each kind of list remembers its own order; vaults share one choice.
  const view = scope.kind === 'type' ? scope.type : scope.kind === 'smart' ? scope.list : scope.kind;
  const groupings = groupingsFor(view, vaults?.length ?? 0);
  const [arrangement, arrange] = useListArrangement(view, groupings);
  // Logins for the same website can share a row in any list that can hold logins, except the
  // one-time codes, where each row shows its code.
  const [combine, setCombine] = useCombineSites();
  const offerSites = !isTrash && !isSmart && scope.kind !== 'codes' && (scope.kind !== 'type' || scope.type === 'login');
  // Lists with networks mark the one the device is on and those in range, while they're open.
  const isWifi = scope.kind === 'type' && scope.type === 'wifi';
  const isEnvironment = scope.kind === 'type' && scope.type === 'environment';
  // Environments are filtered by the project and stage they belong to.
  const projectChoices = useMemo(() => [...new Set((items ?? []).map((item) => item.project).filter((one): one is string => Boolean(one)))].sort(), [items]);
  const stageChoices = useMemo(
    () => [...new Set((items ?? []).map((item) => item.stage).filter((one): one is string => Boolean(one)))].sort(),
    [items],
  );
  const visible = isEnvironment && items ? items.filter((item) => (!projectFilter || item.project === projectFilter) && (!stageFilter || item.stage === stageFilter)) : items;
  const radar = useWifiRadar(isWifi || Boolean(items?.some((item) => item.type === 'wifi')));
  // Search results and the trash keep the order they come in (by name, and newest deletion first),
  // and so do the smart lists.
  const plain = Boolean(deferredQuery) || isTrash || isSmart;
  // The Wi-Fi list puts the networks in range first, the connected one at the top.
  const { nearby, rest } = isWifi && !plain && visible ? nearbyFirst(visible, radar) : { nearby: [], rest: visible };
  const arranged = useSections(rest, arrangement, vaults, offerSites && combine);
  const sections = nearby.length ? [{ key: IN_RANGE_SECTION, items: nearby }, ...arranged] : arranged;

  useShortcuts({
    '/': (event) => {
      event.preventDefault();
      searchRef.current?.focus();
    },
    'mod+c': (event) => {
      const id = (document.activeElement as HTMLElement | null)?.dataset.itemId;
      if (!id || window.getSelection()?.toString()) return;
      event.preventDefault();
      void service.getItem(id).then((item) => {
        const password = loginDetails(item)?.password;
        if (password) void copy(password, t('fields.password')).then(() => usage.record(id));
      });
    },
  });

  function newItem(type: ItemType) {
    if (TOOL_MADE.has(type)) return void navigate('/tools');
    navigate(`/items/${scope.kind === 'type' || scope.kind === 'all' || scope.kind === 'vault' ? scopeKey : 'all'}/new?type=${type}`);
  }

  function onListKey(event: KeyboardEvent) {
    if (event.key !== 'ArrowDown' && event.key !== 'ArrowUp') return;
    const rows = Array.from(listRef.current?.querySelectorAll<HTMLElement>(ROW_SELECTOR) ?? []);
    const index = rows.indexOf(document.activeElement as HTMLElement);
    const next = rows[event.key === 'ArrowDown' ? Math.min(rows.length - 1, index + 1) : Math.max(0, index - 1)];
    if (next) {
      event.preventDefault();
      next.focus();
    }
  }

  return (
    <div className={styles.page} data-view={showingList ? 'list' : 'detail'}>
      <section className={styles.listPane} aria-labelledby="list-title">
        <header className={styles.header}>
          <div className={styles.titleRow}>
            <IconButton icon="menu" label={t('nav.openMenu')} className={styles.menuButton} onClick={openDrawer} />
            <h1 id="list-title" className={styles.title}>
              {title}
            </h1>
            {vault && vault.type !== 'personal' && service.sharing && (
              <IconButton icon="users" label={t('vault.members')} onClick={() => navigate(`/sharing/vaults/${vault.id}`)} />
            )}
            {isWifi && <WifiListTools radar={radar} />}
            {!isTrash && !isSmart && <SortMenu value={arrangement} groupings={groupings} onChange={arrange} combineSites={offerSites ? { on: combine, onChange: setCombine } : undefined} />}
            {canAdd && (
              <Menu
                label={t('list.newItemMenu')}
                items={[
                  ...ITEM_TYPES.filter((type) => (type !== 'document' || service.attachments) && !TOOL_MADE.has(type)).map((type) => ({
                    key: type,
                    label: t(`types.${type}` as MessageKey),
                    icon: TYPE_ICONS[type],
                    onSelect: () => newItem(type),
                  })),
                  { key: 'scan', label: t('otp.scanMenu'), icon: 'qrCode' as const, onSelect: () => setScanning(true) },
                ]}
                trigger={(props) => <IconButton icon="plus" label={t('list.newItem')} tone="active" {...props} />}
              />
            )}
          </div>
          <div className={styles.search}>
            <Icon name="search" size={18} />
            <input
              ref={searchRef}
              type="search"
              aria-label={t('list.search')}
              placeholder={items && !deferredQuery ? t('list.searchPlaceholder', { count: items.length }) : t('list.search')}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Escape') setQuery('');
                if (e.key === 'ArrowDown') {
                  e.preventDefault();
                  listRef.current?.querySelector<HTMLElement>(ROW_SELECTOR)?.focus();
                }
              }}
            />
            <kbd className={styles.kbd} aria-hidden="true">
              /
            </kbd>
          </div>
          {isEnvironment && (projectChoices.length > 0 || stageChoices.length > 0) && (
            <div className={styles.filters}>
              {projectChoices.length > 0 && (
                <label className={styles.filter}>
                  <span>{t('env.filterProject')}</span>
                  <select value={projectFilter} onChange={(e) => setProjectFilter(e.target.value)}>
                    <option value="">{t('env.allProjects')}</option>
                    {projectChoices.map((project) => (
                      <option key={project} value={project}>
                        {project}
                      </option>
                    ))}
                  </select>
                </label>
              )}
              {stageChoices.length > 0 && (
                <label className={styles.filter}>
                  <span>{t('env.filterStage')}</span>
                  <select value={stageFilter} onChange={(e) => setStageFilter(e.target.value)}>
                    <option value="">{t('env.allStages')}</option>
                    {stageChoices.map((stage) => (
                      <option key={stage} value={stage}>
                        {stageLabel(stage)}
                      </option>
                    ))}
                  </select>
                </label>
              )}
            </div>
          )}
          {isTrash && items && items.length > 0 && <p className={styles.note}>{t('trash.note', { days: TRASH_DAYS })}</p>}
          {deferredQuery && !isTrash && !isSmart && (arrangement.grouping !== 'none' || arrangement.sort !== 'name') && items && items.length > 0 && <p className={styles.note}>{t('list.searchNote')}</p>}
          {vault?.untrusted && <Alert tone="warn">{t('vault.untrustedBody', { vault: vault.name })}</Alert>}
          {isWifi && radar && <WifiPermissionNote radar={radar} />}
        </header>

        <div className={styles.listScroll}>
          {error ? (
            <EmptyState icon="alert" title={t('list.loadFailed')} action={<Button variant="secondary" onClick={retry}>{t('common.tryAgain')}</Button>} />
          ) : !visible ? (
            <ListSkeleton />
          ) : visible.length === 0 && !deferredQuery && (projectFilter || stageFilter) ? (
            <EmptyState icon="search" title={t('env.noMatches')} action={<Button variant="secondary" onClick={() => { setProjectFilter(''); setStageFilter(''); }}>{t('env.clearFilters')}</Button>} />
          ) : items!.length === 0 ? (
            <ListEmpty scope={scope} query={deferredQuery} onClear={() => setQuery('')} onAdd={() => newItem(scope.kind === 'type' ? scope.type : 'login')} onImport={() => navigate('/settings#import')} />
          ) : (
            <>
              <p className="visually-hidden" role="status">
                {deferredQuery ? t('list.results', { count: visible.length }) : ''}
              </p>
              <ItemSections
                sections={plain ? [{ key: '', items: visible }] : sections}
                grouping={plain ? 'none' : arrangement.grouping}
                vaults={vaults}
                listClassName={styles.list}
                containerRef={listRef}
                onKeyDown={onListKey}
                renderItem={(item) => <ItemRow key={item.id} item={item} scopeKey={scopeKey} trash={isTrash} codes={scope.kind === 'codes'} vaults={vaults} radar={radar} />}
              />
            </>
          )}
        </div>
      </section>

      <section className={styles.detailPane} aria-label={t('detail.region')}>
        <Outlet />
      </section>
      <ScanCodesDialog open={scanning} onClose={() => setScanning(false)} />
    </div>
  );
}

/** A list row. In the one-time codes list it also shows the current code, which copies when clicked. */
function ItemRow({ item, scopeKey, trash, codes, vaults, radar }: { item: ItemSummary; scopeKey: string; trash: boolean; codes: boolean; vaults: Vault[] | undefined; radar: WifiRadarState | undefined }) {
  const vault = vaults?.find((v) => v.id === item.vaultId);
  const subtitle = trash ? t('trash.daysLeft', { count: daysLeft(item.deletedAt!) }) : item.subtitle;
  return (
    <li className={codes ? styles.codeRow : undefined}>
      <NavLink to={`/items/${scopeKey}/${item.id}`} data-item-id={item.id} className={({ isActive }) => [styles.row, isActive && styles.rowOn].filter(Boolean).join(' ')}>
        <ItemAvatar name={item.title} urls={item.urls} />
        <span className={styles.rowText}>
          <span className={styles.rowTitle}>
            <bdi>{item.title || t('detail.untitled')}</bdi>
            {item.favorite && <Icon name="star" size={13} className={styles.star} label={t('list.favorite')} />}
            {item.pinned && <Icon name="pin" size={13} className={styles.pin} label={t('list.pinned')} />}
          </span>
          <span className={styles.rowSub}>
            <bdi>{subtitle}</bdi>
            {item.type === 'environment' && item.stage && (
              <span className={styles.stageChip} data-stage={item.stage.toLowerCase()}>
                {stageLabel(item.stage)}
              </span>
            )}
            {vault?.type === 'shared' && scopeKey !== `v-${vault.id}` && <span className={styles.vaultTag}>{vault.name}</span>}
          </span>
        </span>
        <span className={styles.flags}>
          {!trash && <WifiMark ssid={wifiSsid(item)} radar={radar} />}
          {item.hasPasskey && <Icon name="passkey" size={15} label={t('list.hasPasskey')} />}
          {item.hasTotp && !codes && <Icon name="clock" size={15} label={t('list.hasTotp')} />}
        </span>
      </NavLink>
      {codes && (
        <ItemUseProvider itemId={item.id}>
          <LiveCode item={item} />
        </ItemUseProvider>
      )}
    </li>
  );
}

function ListSkeleton() {
  return (
    <ul className={styles.list} aria-busy="true" aria-label={t('common.loading')}>
      {Array.from({ length: 7 }, (_, i) => (
        <li key={i} className={styles.skeleton}>
          <span />
          <span>
            <i />
            <i />
          </span>
        </li>
      ))}
    </ul>
  );
}

function ListEmpty({ scope, query, onClear, onAdd, onImport }: { scope: Scope; query: string; onClear: () => void; onAdd: () => void; onImport: () => void }) {
  if (query) {
    return (
      <EmptyState icon="search" title={t('empty.searchTitle', { query })} action={<Button variant="secondary" onClick={onClear}>{t('empty.clearSearch')}</Button>}>
        {t('empty.searchBody')}
      </EmptyState>
    );
  }
  // Recently created and Recently modified are only empty when the vault is.
  if (scope.kind === 'smart' && (scope.list === 'frequent' || scope.list === 'used')) {
    return (
      <EmptyState icon={scope.list === 'frequent' ? 'trending' : 'history'} title={t('empty.usedTitle')}>
        {t(scope.list === 'frequent' ? 'empty.frequentBody' : 'empty.usedBody')}
      </EmptyState>
    );
  }
  switch (scope.kind) {
    case 'trash':
      return <EmptyState icon="trash" title={t('empty.trashTitle')}>{t('empty.trashBody')}</EmptyState>;
    case 'favorites':
      return <EmptyState icon="star" title={t('empty.favoritesTitle')}>{t('empty.favoritesBody')}</EmptyState>;
    case 'pinned':
      return <EmptyState icon="pin" title={t('empty.pinnedTitle')}>{t('empty.pinnedBody')}</EmptyState>;
    case 'passkeys':
      return <EmptyState icon="passkey" title={t('empty.passkeysTitle')}>{t('empty.passkeysBody')}</EmptyState>;
    case 'codes':
      return <EmptyState icon="clock" title={t('empty.codesTitle')}>{t('empty.codesBody')}</EmptyState>;
    default:
      return (
        <EmptyState
          icon="vault"
          title={t('empty.vaultTitle')}
          action={
            <div className={styles.emptyActions}>
              <Button icon="plus" onClick={onAdd}>{t('empty.addItem')}</Button>
              <Button variant="ghost" icon="upload" onClick={onImport}>
                {t('empty.import')}
              </Button>
            </div>
          }
        >
          {t('empty.vaultBody')}
        </EmptyState>
      );
  }
}

/** The detail pane before anything is selected: a quiet nudge plus the keyboard shortcuts. */
export function NoSelection() {
  return (
    <div className={styles.noSelection}>
      <Logo variant="mark" size={64} />
      <p className={styles.noSelectionTitle}>{t('detail.noSelection')}</p>
      <dl className={styles.shortcuts}>
        <div>
          <dt><kbd>/</kbd></dt>
          <dd>{t('shortcuts.search')}</dd>
        </div>
        <div>
          <dt><kbd>N</kbd></dt>
          <dd>{t('shortcuts.newItem')}</dd>
        </div>
        <div>
          <dt><kbd>{navigator.platform.startsWith('Mac') ? '⌘' : 'Ctrl'}</kbd><kbd>C</kbd></dt>
          <dd>{t('shortcuts.copyPassword')}</dd>
        </div>
      </dl>
    </div>
  );
}
