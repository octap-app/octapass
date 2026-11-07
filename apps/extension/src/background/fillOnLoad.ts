// Fill on page load (plan 05, History 2026-11-06): off unless the user turns it on in Settings, per
// device. With it on, a login form in a top-level https page is filled as it shows, with the login
// last used on that exact host (or its only one). Every other fill still waits for the user's pick.

import type { ItemSummary, ItemUse } from '@octapass/vault-client';

/** "Fill logins when a page opens", kept by the popup in `chrome.storage.local`. Off unless set to true. */
export const FILL_ON_LOAD_KEY = 'octapass:fillOnLoad';

export async function fillOnLoadEnabled(): Promise<boolean> {
  try {
    return (await chrome.storage.local.get(FILL_ON_LOAD_KEY))[FILL_ON_LOAD_KEY] === true;
  } catch {
    return false;
  }
}

const time = (text: string | undefined) => (text ? Date.parse(text) || 0 : 0);

/**
 * Which of the page's own logins to fill: the one used last (a fill or a copy, on any device), or
 * the only one. Several never used is a guess, so none.
 */
export function loginToFill(logins: ItemSummary[], usage: Readonly<Record<string, ItemUse>>): ItemSummary | undefined {
  let best: ItemSummary | undefined;
  let bestTime = 0;
  for (const login of logins) {
    const used = time(usage[login.id]?.lastUsedAt);
    if (used > bestTime) {
      best = login;
      bestTime = used;
    }
  }
  return best ?? (logins.length === 1 ? logins[0] : undefined);
}
