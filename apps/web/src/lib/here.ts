import type { Here, LocationPermission, LocationService } from '@octapass/vault-client';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useService } from '../app/ServiceContext';
import { useWifiRadar } from './wifi';

// Nearby's two ways of knowing where the device is: the Wi-Fi network it's on (apps that can see
// Wi-Fi), and one reading of its location when the user has turned that on. Both stay on the
// device: they're handed to the core, which compares them with the places in the vault.

const LOCATION_KEY = 'octapass:nearby-location';
const SUGGEST_KEY = 'octapass:nearby-suggest';

function readFlag(key: string, fallback: boolean): boolean {
  try {
    const value = localStorage.getItem(key);
    return value === null ? fallback : value === 'on';
  } catch {
    return fallback;
  }
}

function writeFlag(key: string, on: boolean): void {
  try {
    localStorage.setItem(key, on ? 'on' : 'off');
  } catch {
    // Without storage the choice lasts until the page closes.
  }
  window.dispatchEvent(new Event(key));
}

function useFlag(key: string, fallback: boolean): [boolean, (on: boolean) => void] {
  const [on, setOn] = useState(() => readFlag(key, fallback));
  useEffect(() => {
    const sync = () => setOn(readFlag(key, fallback));
    window.addEventListener(key, sync);
    return () => window.removeEventListener(key, sync);
  }, [key, fallback]);
  return [on, useCallback((next: boolean) => writeFlag(key, next), [key])];
}

/** Whether Nearby reads this device's location. Off until the user turns it on; device-only. */
export function useLocationSetting(): [boolean, (on: boolean) => void] {
  return useFlag(LOCATION_KEY, false);
}

/** Whether a new item saved at a place is offered to it. On by default; device-only. */
export function useSuggestSetting(): [boolean, (on: boolean) => void] {
  return useFlag(SUGGEST_KEY, true);
}

/** The browser's location: one reading, coarse is fine, a minute old at most. */
export const browserLocation: LocationService = {
  async permission(): Promise<LocationPermission> {
    if (typeof navigator === 'undefined' || !navigator.geolocation) return 'unavailable';
    try {
      const status = await navigator.permissions?.query({ name: 'geolocation' });
      return status ? (status.state as LocationPermission) : 'prompt';
    } catch {
      return 'prompt';
    }
  },
  current() {
    return new Promise((resolve, reject) => {
      if (typeof navigator === 'undefined' || !navigator.geolocation) return reject(new Error('unavailable'));
      navigator.geolocation.getCurrentPosition(
        ({ coords }) => resolve({ latitude: coords.latitude, longitude: coords.longitude, accuracy: coords.accuracy }),
        (error) => reject(new Error(error.code === error.PERMISSION_DENIED ? 'denied' : 'unavailable')),
        { enableHighAccuracy: false, maximumAge: 60_000, timeout: 15_000 },
      );
    });
  },
};

export function useLocationService(): LocationService {
  return useService().location ?? browserLocation;
}

/** `off`: the setting is off. `denied`: the system refused. `unavailable`: no reading to be had. */
export type LocationState = 'off' | 'reading' | 'ok' | 'denied' | 'unavailable';

export interface HereState {
  here: Here;
  /** The Wi-Fi network the device is on, when the host can see it. */
  network?: string;
  /** Whether this host can see Wi-Fi at all (the desktop app; not a browser or the extension). */
  wifiVisible: boolean;
  location: LocationState;
  /** True until the first answer from Wi-Fi and location is in. */
  checking: boolean;
  /** Reads the location again (and asks for permission if needed). */
  refresh: () => void;
}

/**
 * Where the device is, while a screen that needs it is open (`active`). The location is read once
 * when it opens and again each time the page comes back to the front: never watched, never kept.
 */
export function useHere(active: boolean): HereState {
  const radar = useWifiRadar(active);
  const locationService = useLocationService();
  const [useLocation] = useLocationSetting();
  const [position, setPosition] = useState<Here['position']>();
  const [location, setLocation] = useState<LocationState>(useLocation ? 'reading' : 'off');
  const run = useRef(0);

  const read = useCallback(() => {
    if (!useLocation) {
      setLocation('off');
      setPosition(undefined);
      return;
    }
    const current = ++run.current;
    setLocation('reading');
    locationService.current().then(
      (reading) => {
        if (current !== run.current) return;
        setPosition(reading);
        setLocation('ok');
      },
      (error: unknown) => {
        if (current !== run.current) return;
        setPosition(undefined);
        setLocation(error instanceof Error && error.message === 'denied' ? 'denied' : 'unavailable');
      },
    );
  }, [useLocation, locationService]);

  useEffect(() => {
    if (!active) return;
    read();
    const onVisible = () => document.visibilityState === 'visible' && read();
    document.addEventListener('visibilitychange', onVisible);
    return () => {
      run.current++;
      document.removeEventListener('visibilitychange', onVisible);
    };
  }, [active, read]);

  const network = radar?.permission === 'granted' ? radar.connected : undefined;
  const here = useMemo<Here>(() => ({ networks: network ? [network] : [], ...(position && { position }) }), [network, position]);
  const wifiChecking = Boolean(radar && radar.permission === undefined);
  return {
    here,
    network,
    wifiVisible: Boolean(radar),
    location,
    checking: wifiChecking || location === 'reading',
    refresh: () => {
      radar?.refresh();
      read();
    },
  };
}

/** Whether the device knows anything about where it is. */
export function knowsWhere(here: Here): boolean {
  return Boolean(here.networks?.length || here.position);
}
