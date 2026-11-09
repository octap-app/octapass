import { Button, Dialog, EmptyState, Icon, IconButton, TextArea, TextField, useToast } from '@octapass/ui';
import {
  formatDistance,
  hasPoint,
  PLACE_DEFAULT_RADIUS,
  PLACE_MAX_RADIUS,
  PLACE_MIN_RADIUS,
  PLACE_TYPE,
  SCHEMA_VERSION,
  withPlace,
  type Item,
  type ItemSummary,
  type NearbyPlace,
  type PlaceData,
  type PlaceDetails,
  type Vault,
} from '@octapass/vault-client';
import { useEffect, useMemo, useState } from 'react';
import { Link, Outlet, useMatch, useNavigate, useOutletContext } from 'react-router';
import { useService } from '../../app/ServiceContext';
import { Alert } from '../../components/Alert';
import { ConfirmDialog } from '../../components/ConfirmDialog';
import { Menu } from '../../components/Menu';
import { getLocale, t } from '../../i18n';
import { errorMessage } from '../../lib/errors';
import { knowsWhere, useHere, useLocationService, useLocationSetting, useSuggestSetting, type HereState } from '../../lib/here';
import { useItems, useLive, useVaults } from '../../lib/useItems';
import { ItemSections } from './ItemSections';
import { ItemRow, ListSkeleton } from './ItemsPage';
import type { LayoutContext } from './VaultLayout';
import pageStyles from './ItemsPage.module.css';
import styles from './Nearby.module.css';

function distanceText(metres: number | undefined): string | undefined {
  return metres === undefined ? undefined : t('nearby.away', { distance: formatDistance(metres, getLocale()) });
}

/** Why no place is marked as nearby, when none is. */
function whyNoneHere(state: HereState): string {
  if (knowsWhere(state.here)) return t('nearby.reasonNoMatch');
  const wifi = state.wifiVisible ? '' : `${t('nearby.reasonNoWifi')} `;
  switch (state.location) {
    case 'denied':
      return wifi + t('nearby.reasonLocationDenied');
    case 'unavailable':
      return wifi + t('nearby.reasonLocationUnavailable');
    case 'off':
      return wifi + t('nearby.reasonLocationOff');
    default:
      return t('nearby.reasonNoMatch');
  }
}

/** /items/nearby: the place the device is at first, its items by type, then the other places. */
export function NearbyPage() {
  const { openDrawer } = useOutletContext<LayoutContext>();
  const service = useService();
  const navigate = useNavigate();
  const vaults = useVaults();
  const state = useHere(true);
  const [useLocation, setUseLocation] = useLocationSetting();
  const { items: places } = useItems({ type: PLACE_TYPE });
  const { items } = useItems({});
  const hereKey = JSON.stringify(state.here);
  const { data: list, error, retry } = useLive(async () => (service.nearby ? service.nearby(state.here) : []), [hereKey]);
  const [managing, setManaging] = useState(false);
  const [editing, setEditing] = useState<ItemSummary | 'new'>();
  // On a narrow screen the list and an open item take turns, as in the other lists.
  const showingList = useMatch('/items/:scope') !== null;

  const byId = useMemo(() => new Map([...(items ?? []), ...(places ?? [])].map((summary) => [summary.id, summary])), [items, places]);
  const anyHere = list?.some((place) => place.here);
  const firstOther = list?.findIndex((place) => !place.here) ?? -1;

  return (
    <div className={pageStyles.page} data-view={showingList ? 'list' : 'detail'}>
      <section className={pageStyles.listPane} aria-labelledby="list-title">
        <header className={pageStyles.header}>
          <div className={pageStyles.titleRow}>
            <IconButton icon="menu" label={t('nav.openMenu')} className={pageStyles.menuButton} onClick={openDrawer} />
            <h1 id="list-title" className={pageStyles.title}>
              {t('scopes.nearby')}
            </h1>
            <IconButton icon="settings" label={t('nearby.places')} onClick={() => setManaging(true)} />
            <IconButton icon="plus" label={t('nearby.newPlace')} tone="active" onClick={() => setEditing('new')} />
          </div>
          {list && list.length > 0 && !anyHere && !state.checking && (
            <p className={styles.status} role="status">
              {whyNoneHere(state)}{' '}
              {!useLocation && (
                <Button variant="ghost" size="sm" icon="mapPin" onClick={() => setUseLocation(true)}>
                  {t('nearby.useLocation')}
                </Button>
              )}
              {state.location === 'unavailable' && (
                <Button variant="ghost" size="sm" onClick={state.refresh}>
                  {t('common.tryAgain')}
                </Button>
              )}
            </p>
          )}
          {state.checking && list && list.length > 0 && (
            <p className={styles.status} role="status">
              {t('nearby.checking')}
            </p>
          )}
        </header>

        <div className={pageStyles.listScroll}>
          {error ? (
            <EmptyState icon="alert" title={t('list.loadFailed')} action={<Button variant="secondary" onClick={retry}>{t('common.tryAgain')}</Button>} />
          ) : !list || !items || !places ? (
            <ListSkeleton />
          ) : list.length === 0 ? (
            <EmptyState icon="mapPin" title={t('nearby.emptyTitle')} action={<Button icon="plus" onClick={() => setEditing('new')}>{t('nearby.newPlace')}</Button>}>
              {t('nearby.emptyBody')}
            </EmptyState>
          ) : (
            <div className={styles.places}>
              {list.map((entry, index) => {
                const place = byId.get(entry.id);
                if (!place) return null;
                return (
                  <PlaceGroup
                    key={entry.id}
                    entry={entry}
                    place={place}
                    byId={byId}
                    vaults={vaults}
                    otherHeading={index === firstOther && anyHere}
                    onEdit={() => setEditing(place)}
                    onAdd={() => navigate(`/items/nearby/new?type=login&place=${encodeURIComponent(entry.id)}`)}
                  />
                );
              })}
              {useLocation && <p className={styles.footnote}>{t('nearby.locationNote')} <Button variant="ghost" size="sm" onClick={() => setUseLocation(false)}>{t('nearby.stopLocation')}</Button></p>}
            </div>
          )}
        </div>
      </section>

      <section className={pageStyles.detailPane} aria-label={t('detail.region')}>
        <Outlet />
      </section>
      <PlacesDialog open={managing} places={places ?? []} vaults={vaults} onClose={() => setManaging(false)} onEdit={(place) => setEditing(place)} onNew={() => setEditing('new')} />
      <PlaceDialog open={editing !== undefined} place={editing === 'new' ? undefined : editing} vaults={vaults} network={state.network} onClose={() => setEditing(undefined)} />
    </div>
  );
}

function PlaceGroup({
  entry,
  place,
  byId,
  vaults,
  otherHeading,
  onEdit,
  onAdd,
}: {
  entry: NearbyPlace;
  place: ItemSummary;
  byId: ReadonlyMap<string, ItemSummary>;
  vaults: Vault[] | undefined;
  otherHeading: boolean | undefined;
  onEdit: () => void;
  onAdd: () => void;
}) {
  const sections = entry.sections
    .map((section) => ({ key: section.type, items: section.items.map((id) => byId.get(id)).filter((one): one is ItemSummary => Boolean(one)) }))
    .filter((section) => section.items.length > 0);
  const vault = vaults?.find((v) => v.id === place.vaultId);
  const canEdit = vault?.role !== 'read' && !vault?.untrusted;
  const how = entry.here === 'wifi' ? t('nearby.byWifi') : entry.here === 'location' ? t('nearby.byLocation') : undefined;
  const away = entry.here ? undefined : distanceText(entry.distance);
  return (
    <>
      {otherHeading && <h2 className={styles.others}>{t('nearby.otherPlaces')}</h2>}
      <section className={styles.place} data-here={entry.here ? 'true' : undefined} aria-labelledby={`place-${entry.id}`} data-testid={`place-${entry.id}`}>
        <header className={styles.placeHead}>
          <Icon name="mapPin" size={18} />
          <div className={styles.placeText}>
            <h2 id={`place-${entry.id}`} className={styles.placeName}>
              <bdi>{entry.here ? t('nearby.nowNearby', { place: place.title }) : place.title}</bdi>
            </h2>
            {(how || away || vault?.type === 'shared') && (
              <p className={styles.placeSub}>
                {[how, away].filter(Boolean).join(' · ')}
                {vault?.type === 'shared' && <span className={pageStyles.vaultTag}>{vault.name}</span>}
              </p>
            )}
          </div>
          {canEdit && <IconButton icon="edit" size="sm" label={t('nearby.editPlace')} onClick={onEdit} />}
          <IconButton icon="plus" size="sm" label={t('nearby.addItemHere')} onClick={onAdd} />
        </header>
        {sections.length === 0 ? (
          <p className={styles.nothing}>{t('nearby.noItems')}</p>
        ) : (
          <ItemSections
            sections={sections}
            grouping="type"
            vaults={vaults}
            className={styles.sections}
            listClassName={pageStyles.list}
            renderItem={(item) => <ItemRow key={item.id} item={item} scopeKey="nearby" trash={false} codes={false} vaults={vaults} radar={undefined} />}
          />
        )}
      </section>
    </>
  );
}

/** A place's one-line description in the manager. */
function placeSummary(place: PlaceData | undefined): string {
  const parts: string[] = [];
  if (hasPoint(place)) parts.push(t('nearby.summaryPoint', { radius: formatDistance(place.radius ?? PLACE_DEFAULT_RADIUS, getLocale()) }));
  if (place?.networks?.length) parts.push(t('nearby.summaryNetworks', { count: place.networks.length }));
  return parts.join(' · ') || t('nearby.summaryNothing');
}

/** The Places manager: every place, to edit or delete, and New place. */
function PlacesDialog({ open, places, vaults, onClose, onEdit, onNew }: { open: boolean; places: ItemSummary[]; vaults: Vault[] | undefined; onClose: () => void; onEdit: (place: ItemSummary) => void; onNew: () => void }) {
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={t('nearby.managerTitle')}
      description={t('nearby.managerBody')}
      closeLabel={t('common.close')}
      size="md"
      footer={
        <Button icon="plus" onClick={() => { onClose(); onNew(); }}>
          {t('nearby.newPlace')}
        </Button>
      }
    >
      <ul className={styles.manager}>
        {places.map((place) => {
          const vault = vaults?.find((v) => v.id === place.vaultId);
          const canEdit = vault?.role !== 'read' && !vault?.untrusted;
          return (
            <li key={place.id}>
              <Icon name="mapPin" size={18} />
              <span className={styles.managerText}>
                <bdi className={styles.managerName}>{place.title}</bdi>
                <span className={styles.placeSub}>
                  {placeSummary(place.place)}
                  {vault && vault.type !== 'personal' && <span className={pageStyles.vaultTag}>{vault.name}</span>}
                </span>
              </span>
              {canEdit && (
                <Button variant="secondary" size="sm" onClick={() => { onClose(); onEdit(place); }}>
                  {t('common.edit')}
                </Button>
              )}
            </li>
          );
        })}
      </ul>
    </Dialog>
  );
}

interface PlaceForm {
  title: string;
  vaultId: string;
  latitude: string;
  longitude: string;
  radius: string;
  networks: string[];
  notes: string;
}

/** The form's place, checked the way the core's `PlaceData::cleaned` checks it; `undefined` when the point is wrong. */
export function placeFromForm(form: Pick<PlaceForm, 'latitude' | 'longitude' | 'radius' | 'networks'>): PlaceData | undefined {
  const place: PlaceData = {};
  const lat = form.latitude.trim();
  const lon = form.longitude.trim();
  if (lat || lon) {
    const latitude = Number(lat.replace(',', '.'));
    const longitude = Number(lon.replace(',', '.'));
    if (!lat || !lon || !Number.isFinite(latitude) || !Number.isFinite(longitude) || Math.abs(latitude) > 90 || Math.abs(longitude) > 180) return undefined;
    place.latitude = Math.round(latitude * 1e6) / 1e6;
    place.longitude = Math.round(longitude * 1e6) / 1e6;
  }
  const radius = Number(form.radius);
  if (form.radius.trim() && Number.isFinite(radius) && Math.round(radius) !== PLACE_DEFAULT_RADIUS) place.radius = Math.round(Math.min(PLACE_MAX_RADIUS, Math.max(PLACE_MIN_RADIUS, radius)));
  const networks = [...new Set(form.networks.filter((ssid) => ssid.trim() && new TextEncoder().encode(ssid).length <= 32))];
  if (networks.length) place.networks = networks.slice(0, 20);
  return place;
}

/** New place or Edit place. */
function PlaceDialog({ open, place, vaults, network, onClose }: { open: boolean; place: ItemSummary | undefined; vaults: Vault[] | undefined; network: string | undefined; onClose: () => void }) {
  const service = useService();
  const toast = useToast();
  const locationService = useLocationService();
  const writable = useMemo(() => (vaults ?? []).filter((v) => v.role !== 'read' && !v.untrusted), [vaults]);
  const [form, setForm] = useState<PlaceForm>();
  const [original, setOriginal] = useState<Item>();
  const [nameError, setNameError] = useState<string>();
  const [pointError, setPointError] = useState<string>();
  const [newNetwork, setNewNetwork] = useState('');
  const [locating, setLocating] = useState(false);
  const [locateError, setLocateError] = useState<string>();
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState<string>();
  const [deleting, setDeleting] = useState(false);

  useEffect(() => {
    if (!open) return;
    setNameError(undefined);
    setPointError(undefined);
    setLocateError(undefined);
    setFormError(undefined);
    setNewNetwork('');
    setOriginal(undefined);
    const data = place?.place ?? {};
    const fallback = writable.find((v) => v.type === 'personal')?.id ?? writable[0]?.id ?? '';
    setForm({
      title: place?.title ?? '',
      vaultId: place?.vaultId ?? fallback,
      latitude: data.latitude?.toString() ?? '',
      longitude: data.longitude?.toString() ?? '',
      radius: String(data.radius ?? PLACE_DEFAULT_RADIUS),
      networks: data.networks ?? [],
      notes: '',
    });
    if (place) {
      void service.getItem(place.id).then((item) => {
        setOriginal(item);
        setForm((f) => f && { ...f, notes: (item.details as PlaceDetails).notes ?? '' });
      });
    }
  }, [open, place, service, writable]);

  if (!form) return null;
  const vault = vaults?.find((v) => v.id === form.vaultId);
  const hasCoordinates = Boolean(form.latitude.trim() || form.longitude.trim());
  const set = (patch: Partial<PlaceForm>) => setForm((f) => f && { ...f, ...patch });
  const addNetwork = (ssid: string) => {
    if (ssid.trim() && !form.networks.includes(ssid)) set({ networks: [...form.networks, ssid] });
    setNewNetwork('');
  };

  async function useCurrent() {
    setLocating(true);
    setLocateError(undefined);
    try {
      const reading = await locationService.current();
      set({ latitude: reading.latitude.toFixed(6), longitude: reading.longitude.toFixed(6) });
      setPointError(undefined);
    } catch {
      setLocateError(t('nearby.locationFailed'));
    } finally {
      setLocating(false);
    }
  }

  async function save() {
    if (!form) return;
    const title = form.title.trim();
    const data = placeFromForm(form);
    setNameError(title ? undefined : t('nearby.nameRequired'));
    setPointError(data ? undefined : t('nearby.invalidPoint'));
    if (!title || !data) return;
    setSaving(true);
    setFormError(undefined);
    try {
      const details: PlaceDetails = { ...(original?.details as PlaceDetails | undefined), schemaVersion: SCHEMA_VERSION };
      if (form.notes.trim()) details.notes = form.notes.trim();
      else delete details.notes;
      const overview = { ...(original?.overview ?? {}), schemaVersion: SCHEMA_VERSION, type: PLACE_TYPE, title, place: data } as Item['overview'];
      await service.saveItem(original ? { id: original.id, vaultId: original.vaultId, revision: original.revision, overview, details } : { vaultId: form.vaultId, overview, details });
      toast({ message: t('nearby.saved', { place: title }), tone: 'success' });
      onClose();
    } catch (e) {
      setFormError(errorMessage(e));
    } finally {
      setSaving(false);
    }
  }

  return (
    <>
      <Dialog
        open={open && !deleting}
        onClose={onClose}
        title={place ? t('nearby.editPlace') : t('nearby.newPlace')}
        closeLabel={t('common.close')}
        size="md"
        footer={
          <>
            {place && (
              <Button variant="ghost" icon="trash" onClick={() => setDeleting(true)}>
                {t('nearby.deletePlace')}
              </Button>
            )}
            <Button variant="secondary" onClick={onClose}>
              {t('common.cancel')}
            </Button>
            <Button busy={saving} disabled={Boolean(place) && !original} onClick={() => void save()}>
              {t('common.save')}
            </Button>
          </>
        }
      >
        <form
          className={styles.form}
          onSubmit={(event) => {
            event.preventDefault();
            void save();
          }}
        >
          {formError && <Alert>{formError}</Alert>}
          <TextField label={t('nearby.name')} placeholder={t('nearby.namePlaceholder')} value={form.title} error={nameError} onChange={(e) => set({ title: e.target.value })} autoFocus />
          {!place && writable.length > 1 && (
            <label className={styles.select}>
              <span>{t('nearby.vault')}</span>
              <select value={form.vaultId} onChange={(e) => set({ vaultId: e.target.value })}>
                {writable.map((v) => (
                  <option key={v.id} value={v.id}>
                    {v.name}
                  </option>
                ))}
              </select>
            </label>
          )}

          <fieldset className={styles.fieldset}>
            <legend>{t('nearby.networks')}</legend>
            <p className={styles.hint}>{t('nearby.networksHint')}</p>
            {form.networks.length > 0 && (
              <ul className={styles.chips}>
                {form.networks.map((ssid) => (
                  <li key={ssid}>
                    <Icon name="wifi" size={14} />
                    <bdi dir="ltr">{ssid}</bdi>
                    <IconButton icon="close" size="sm" label={t('nearby.removeNetwork', { network: ssid })} onClick={() => set({ networks: form.networks.filter((one) => one !== ssid) })} />
                  </li>
                ))}
              </ul>
            )}
            <div className={styles.addRow}>
              <TextField
                label={t('nearby.networkPlaceholder')}
                hideLabel
                placeholder={t('nearby.networkPlaceholder')}
                value={newNetwork}
                maxLength={32}
                onChange={(e) => setNewNetwork(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    e.preventDefault();
                    addNetwork(newNetwork);
                  }
                }}
              />
              <Button variant="secondary" disabled={!newNetwork.trim()} onClick={() => addNetwork(newNetwork)}>
                {t('nearby.addNetwork')}
              </Button>
            </div>
            {network && !form.networks.includes(network) && (
              <Button variant="ghost" size="sm" icon="wifi" onClick={() => addNetwork(network)}>
                {t('nearby.addConnected', { network })}
              </Button>
            )}
          </fieldset>

          <fieldset className={styles.fieldset}>
            <legend>{t('nearby.location')}</legend>
            <p className={styles.hint}>{t('nearby.locationHint')}</p>
            <div className={styles.coords}>
              <TextField label={t('nearby.latitude')} inputMode="decimal" mono value={form.latitude} error={pointError} onChange={(e) => set({ latitude: e.target.value })} />
              <TextField label={t('nearby.longitude')} inputMode="decimal" mono value={form.longitude} onChange={(e) => set({ longitude: e.target.value })} />
            </div>
            <div className={styles.addRow}>
              <Button variant="secondary" icon="mapPin" busy={locating} onClick={() => void useCurrent()}>
                {locating ? t('nearby.locating') : t('nearby.useCurrent')}
              </Button>
              {hasCoordinates && (
                <Button variant="ghost" onClick={() => set({ latitude: '', longitude: '' })}>
                  {t('nearby.clearLocation')}
                </Button>
              )}
            </div>
            {locateError && <Alert tone="warn">{locateError}</Alert>}
            <TextField label={t('nearby.radius')} hint={t('nearby.radiusHint')} type="number" min={PLACE_MIN_RADIUS} max={PLACE_MAX_RADIUS} step={5} value={form.radius} onChange={(e) => set({ radius: e.target.value })} />
            {hasCoordinates && vault && vault.type !== 'personal' && <Alert tone="warn">{t('nearby.sharedWarning', { vault: vault.name })}</Alert>}
          </fieldset>
          {!hasCoordinates && form.networks.length === 0 && <p className={styles.hint}>{t('nearby.noWay')}</p>}

          <TextArea label={t('nearby.notes')} value={form.notes} rows={3} onChange={(e) => set({ notes: e.target.value })} />
          <button type="submit" hidden />
        </form>
      </Dialog>
      <ConfirmDialog
        open={deleting}
        title={t('nearby.deletePlace')}
        confirmLabel={t('nearby.deletePlace')}
        onClose={() => setDeleting(false)}
        onConfirm={async () => {
          await service.deleteItem(place!.id);
          toast({ message: t('nearby.deleted', { place: place!.title }), tone: 'success' });
          setDeleting(false);
          onClose();
        }}
      >
        {t('nearby.deleteConfirm', { place: place?.title ?? '' })}
      </ConfirmDialog>
    </>
  );
}

/** An item's places in its detail view, with Add to a place and a way to take it off one. */
export function ItemPlaces({ item, editable }: { item: Item; editable: boolean }) {
  const service = useService();
  const toast = useToast();
  const { items: places } = useItems({ type: PLACE_TYPE });
  if (item.overview.type === PLACE_TYPE || !places) return null;
  const linked = places.filter((place) => item.overview.places?.includes(place.id));
  const others = places.filter((place) => !item.overview.places?.includes(place.id));
  if (!linked.length && (!editable || !places.length)) return null;

  const change = (place: ItemSummary, on: boolean) =>
    service
      .saveItem({ ...item, overview: { ...item.overview, places: withPlace(item.overview.places, place.id, on) } })
      .then(
        () => toast({ message: t(on ? 'nearby.addedTo' : 'nearby.removedFrom', { place: place.title }), tone: 'success' }),
        (e: unknown) => toast({ message: errorMessage(e), tone: 'danger' }),
      );

  return (
    <section className={styles.itemPlaces} aria-label={t('nearby.itemPlaces')}>
      <h2 className={styles.itemPlacesTitle}>{t('nearby.itemPlaces')}</h2>
      <ul className={styles.chips}>
        {linked.map((place) => (
          <li key={place.id}>
            <Icon name="mapPin" size={14} />
            <Link to={`/items/nearby`}>
              <bdi>{place.title}</bdi>
            </Link>
            {editable && <IconButton icon="close" size="sm" label={t('nearby.removeFromPlace', { place: place.title })} onClick={() => void change(place, false)} />}
          </li>
        ))}
        {editable && others.length > 0 && (
          <li className={styles.addChip}>
            <Menu
              label={t('nearby.addToPlace')}
              align="start"
              items={others.map((place) => ({ key: place.id, label: place.title, icon: 'mapPin' as const, onSelect: () => void change(place, true) }))}
              trigger={(props) => (
                <Button variant="ghost" size="sm" icon="plus" {...props}>
                  {t('nearby.addToPlace')}
                </Button>
              )}
            />
          </li>
        )}
      </ul>
    </section>
  );
}

const ASKED_KEY = 'octapass:nearby-asked';

function askedBefore(id: string): boolean {
  try {
    return (JSON.parse(localStorage.getItem(ASKED_KEY) ?? '[]') as string[]).includes(id);
  } catch {
    return false;
  }
}

function markAsked(id: string): void {
  try {
    const asked = (JSON.parse(localStorage.getItem(ASKED_KEY) ?? '[]') as string[]).filter((one) => one !== id);
    localStorage.setItem(ASKED_KEY, JSON.stringify([...asked, id].slice(-200)));
  } catch {
    // Without storage the question can't come back anyway: it's only asked right after saving.
  }
}

/**
 * "You're at Office. Add this item to it?", right after a new item is saved, when the device is at
 * a place its readers can all see (`VaultService.suggestPlace`). Asked once per item; Settings turns it off.
 */
export function PlaceSuggestion({ item, fresh }: { item: Item; fresh: boolean }) {
  const service = useService();
  const toast = useToast();
  const [enabled] = useSuggestSetting();
  const active = fresh && enabled && Boolean(service.suggestPlace) && !askedBefore(item.id);
  const state = useHere(active);
  const [placeId, setPlaceId] = useState<string>();
  const [done, setDone] = useState(false);
  const { items: places } = useItems({ type: PLACE_TYPE });
  const hereKey = JSON.stringify(state.here);

  useEffect(() => {
    if (!active || done || state.checking || !knowsWhere(state.here)) return;
    let live = true;
    void service.suggestPlace!(item.id, state.here).then((id) => {
      if (!live || !id) return;
      setPlaceId(id);
      markAsked(item.id);
    });
    return () => {
      live = false;
    };
    // `item` changes when it's saved again; the question is about the item, so its id is enough.
  }, [active, done, state.checking, hereKey, item.id, service]);

  const place = places?.find((one) => one.id === placeId);
  if (!place || done) return null;
  const answer = (add: boolean) => {
    setDone(true);
    if (!add) return;
    void service.saveItem({ ...item, overview: { ...item.overview, places: withPlace(item.overview.places, place.id, true) } }).then(
      () => toast({ message: t('nearby.addedTo', { place: place.title }), tone: 'success' }),
      (e: unknown) => toast({ message: errorMessage(e), tone: 'danger' }),
    );
  };
  return (
    <div className={styles.suggest} role="status">
      <Icon name="mapPin" size={18} />
      <p>{t('nearby.suggest', { place: place.title })}</p>
      <Button size="sm" onClick={() => answer(true)}>
        {t('nearby.suggestAdd')}
      </Button>
      <Button size="sm" variant="ghost" onClick={() => answer(false)}>
        {t('nearby.suggestNotNow')}
      </Button>
    </div>
  );
}
