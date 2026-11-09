import type { BrowserExtensionService, BrowserExtensionStatus } from '@octapass/vault-client';
import { useCallback, useEffect, useState } from 'react';
import { getLocale } from '../i18n';

/** The offer closed with ×, on this device: `localStorage`, never synced. Settings keeps its links. */
export const EXTENSION_OFFER_DISMISSED = 'octapass.extensionOffer:dismissed';

/**
 * What the vault window offers, from what the app knows (plan 19, History 2026-11-09):
 * - `get`: no Octa Pass extension has ever reached the app, so it's most likely not installed, and
 *   this computer has a browser it works in.
 * - `connect`: one has, but no browser is connected now, so it can't reach the app any more.
 */
export function extensionOffer(status: BrowserExtensionStatus): 'get' | 'connect' | undefined {
  if (status.seen.length > 0) return status.connected.length === 0 ? 'connect' : undefined;
  return status.browsers.length > 0 ? 'get' : undefined;
}

/** "Chrome and Firefox", in the vault's language. */
export function listBrowsers(names: readonly string[]): string {
  try {
    return new Intl.ListFormat(getLocale(), { type: 'conjunction' }).format(names);
  } catch {
    return names.join(', ');
  }
}

export function offerDismissed(): boolean {
  try {
    return localStorage.getItem(EXTENSION_OFFER_DISMISSED) !== null;
  } catch {
    return false;
  }
}

export function dismissOffer(): void {
  try {
    localStorage.setItem(EXTENSION_OFFER_DISMISSED, new Date().toISOString());
  } catch {
    // Offered again next time.
  }
}

/** The status, loaded once and replaced by what connecting or disconnecting returns. */
export function useBrowserExtension(extension: BrowserExtensionService | undefined) {
  const [status, setStatus] = useState<BrowserExtensionStatus>();

  useEffect(() => {
    let live = true;
    extension?.status().then(
      (next) => live && setStatus(next),
      () => undefined,
    );
    return () => {
      live = false;
    };
  }, [extension]);

  const run = useCallback(async (action: () => Promise<BrowserExtensionStatus>) => {
    const next = await action();
    setStatus(next);
    return next;
  }, []);

  return { status, run };
}
