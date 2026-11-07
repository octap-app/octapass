// "Never for this site" on a save prompt: the site and what not to offer there (logins, addresses,
// cards or API keys). Kept in the service worker's own IndexedDB, like frame approvals, and listed in the settings.

import type { Matcher } from './matching';
import type { KeyValueStore } from './storage';

const KEY = 'neverSave';

export type SaveKind = 'login' | 'identity' | 'card' | 'apiKey';

export interface NeverSaveEntry {
  /** The site, as `Matcher.site` names it. */
  site: string;
  kind: SaveKind;
  addedAt: string;
}

export class NeverSave {
  constructor(
    private readonly store: KeyValueStore,
    private readonly matcher: Pick<Matcher, 'site'>,
    private readonly now = () => Date.now(),
  ) {}

  async list(): Promise<NeverSaveEntry[]> {
    return (await this.store.get<NeverSaveEntry[]>(KEY)) ?? [];
  }

  async has(kind: SaveKind, url: string): Promise<boolean> {
    const site = this.matcher.site(url);
    return !!site && (await this.list()).some((e) => e.site === site && e.kind === kind);
  }

  async add(kind: SaveKind, url: string): Promise<void> {
    const site = this.matcher.site(url);
    if (!site || (await this.has(kind, url))) return;
    await this.store.set(KEY, [...(await this.list()), { site, kind, addedAt: new Date(this.now()).toISOString() }]);
  }

  async remove(site: string, kind: SaveKind): Promise<void> {
    await this.store.set(KEY, (await this.list()).filter((e) => e.site !== site || e.kind !== kind));
  }
}
