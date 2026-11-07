import { sightingsByName, upgradeLegacyWifiItems, type ItemDraft, type WifiPermission, type WifiService, type WifiSighting } from '@octapass/vault-client';
import { useEffect, useRef, useSyncExternalStore } from 'react';
import { useService } from '../app/ServiceContext';

/** What the device's Wi-Fi shows right now. Empty until the system allows network names. */
export interface WifiRadarState {
  permission?: WifiPermission;
  connected?: string;
  sightings: ReadonlyMap<string, WifiSighting>;
  scanning: boolean;
}

/** How often the open Wi-Fi screens ask again: Android allows only a few scans a minute anyway. */
export const RADAR_INTERVAL_MS = 15_000;

const EMPTY: WifiRadarState = { sightings: new Map(), scanning: false };

/**
 * One poller per service, shared by every screen that shows Wi-Fi marks. It runs only while one of
 * them is open and the app is visible: never in the background.
 */
class Radar {
  state: WifiRadarState = EMPTY;
  private readonly listeners = new Set<() => void>();
  private users = 0;
  private timer: ReturnType<typeof setInterval> | undefined;
  private run = 0;

  constructor(readonly wifi: WifiService) {}

  subscribe = (listener: () => void) => {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  };

  /** Starts polling for a screen; returns its release. */
  acquire(): () => void {
    if (this.users++ === 0) {
      document.addEventListener('visibilitychange', this.onVisibility);
      this.start(true);
    }
    return () => {
      if (--this.users > 0) return;
      document.removeEventListener('visibilitychange', this.onVisibility);
      this.stop();
    };
  }

  async refresh(rescan: boolean): Promise<void> {
    const run = ++this.run;
    this.set({ scanning: rescan });
    try {
      const permission = await this.wifi.permission();
      if (permission !== 'granted') {
        if (run === this.run) this.set({ permission, connected: undefined, sightings: new Map(), scanning: false });
        return;
      }
      const [connected, nearby] = await Promise.all([this.wifi.currentNetwork(), this.wifi.features.nearby ? this.wifi.nearbyNetworks(rescan) : Promise.resolve([])]);
      if (run === this.run) this.set({ permission, connected, sightings: sightingsByName(nearby), scanning: false });
    } catch {
      if (run === this.run) this.set({ scanning: false });
    }
  }

  async requestPermission(): Promise<void> {
    const permission = await this.wifi.requestPermission().catch(() => 'denied' as const);
    this.set({ permission });
    if (permission === 'granted') await this.refresh(true);
  }

  private start(rescan: boolean) {
    if (document.visibilityState === 'hidden') return;
    void this.refresh(rescan);
    this.timer ??= setInterval(() => void this.refresh(false), RADAR_INTERVAL_MS);
  }

  private stop() {
    clearInterval(this.timer);
    this.timer = undefined;
    this.run++;
  }

  private onVisibility = () => {
    if (document.visibilityState === 'hidden') this.stop();
    else this.start(false);
  };

  private set(patch: Partial<WifiRadarState>) {
    this.state = { ...this.state, ...patch };
    for (const listener of this.listeners) listener();
  }
}

const radars = new WeakMap<WifiService, Radar>();

function radarFor(wifi: WifiService): Radar {
  let radar = radars.get(wifi);
  if (!radar) radars.set(wifi, (radar = new Radar(wifi)));
  return radar;
}

const noSubscribe = () => () => {};

/**
 * The connected and in-range networks, kept fresh while `active` (a Wi-Fi screen is open). Missing
 * where the host has no Wi-Fi (the web vault, the extension).
 */
export function useWifiRadar(active: boolean): (WifiRadarState & { refresh: () => void; requestPermission: () => void; wifi: WifiService }) | undefined {
  const wifi = useService().wifi;
  const radar = wifi ? radarFor(wifi) : undefined;
  const state = useSyncExternalStore(radar?.subscribe ?? noSubscribe, () => radar?.state ?? EMPTY);
  useEffect(() => (radar && active ? radar.acquire() : undefined), [radar, active]);
  if (!radar || !wifi) return undefined;
  return { ...state, wifi, refresh: () => void radar.refresh(true), requestPermission: () => void radar.requestPermission() };
}

// ---------- "Save this network?" ----------

const OFFERS_KEY = 'octapass:wifi-offers';

/** Networks already offered (asked once) and the ones the user said never to. Device-only, like settings. */
export interface WifiOffers {
  asked: string[];
  never: string[];
}

export function loadOffers(): WifiOffers {
  try {
    const stored = JSON.parse(localStorage.getItem(OFFERS_KEY) ?? '{}') as Partial<WifiOffers>;
    return { asked: stored.asked ?? [], never: stored.never ?? [] };
  } catch {
    return { asked: [], never: [] };
  }
}

export function saveOffers(offers: WifiOffers): void {
  try {
    localStorage.setItem(OFFERS_KEY, JSON.stringify(offers));
  } catch {
    // Without storage the offer may come back once more next time.
  }
}

// A network to save goes to the editor in memory, not in the URL or history state: it can hold a password.
let pendingDraft: ItemDraft | undefined;

export function setPendingDraft(draft: ItemDraft): void {
  pendingDraft = draft;
}

/** The draft the next new item should start from. The editor clears it once it has opened. */
export function pendingWifiDraft(): ItemDraft | undefined {
  return pendingDraft;
}

export function clearPendingDraft(): void {
  pendingDraft = undefined;
}

// ---------- Older Wi-Fi items ----------

/** Moves older Wi-Fi items (password items with an SSID field) to the Wi-Fi type, now and when items change. */
export function useLegacyWifiUpgrade(): void {
  const service = useService();
  const checked = useRef(new Map<string, string>());
  useEffect(() => {
    let live = true;
    let running = false;
    let again = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const run = async () => {
      if (running) {
        again = true;
        return;
      }
      running = true;
      try {
        await upgradeLegacyWifiItems(service, checked.current);
      } catch {
        // Offline or locked meanwhile: the next change tries again.
      } finally {
        running = false;
        if (again && live) {
          again = false;
          void run();
        }
      }
    };
    void run();
    const unsubscribe = service.onItemsChange(() => {
      clearTimeout(timer);
      timer = setTimeout(() => void run(), 2000);
    });
    return () => {
      live = false;
      clearTimeout(timer);
      unsubscribe();
    };
  }, [service]);
}
