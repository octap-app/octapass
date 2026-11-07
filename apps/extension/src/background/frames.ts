// Frames from other sites (plan 05): a sign-in widget or payment form that another site embeds gets
// nothing from Octa Pass until the user allows that frame's origin on that site. The inline menu
// asks first, naming both as the browser reports them. Frames from the page's own site (same
// registrable domain) need no approval. Approvals live in the service worker's own IndexedDB, which
// content scripts can't read, and the settings list them.

import type { Matcher } from './matching';
import type { PageSender } from './senders';
import type { KeyValueStore } from './storage';

const KEY = 'frameApprovals';

export interface FrameApproval {
  /** The top-level page's site, as `Matcher.site` names it. */
  site: string;
  /** The frame's origin. */
  origin: string;
  approvedAt: string;
}

/** What a frame may do: everything, or ask first (with the names to show), or nothing at all. */
export type FrameAccess = { allowed: true } | { allowed: false; ask?: { frameHost: string; site: string } };

export class FrameApprovals {
  constructor(
    private readonly store: KeyValueStore,
    private readonly matcher: Pick<Matcher, 'site' | 'sameSite'>,
    private readonly now = () => Date.now(),
  ) {}

  async list(): Promise<FrameApproval[]> {
    return (await this.store.get<FrameApproval[]>(KEY)) ?? [];
  }

  async check(page: PageSender): Promise<FrameAccess> {
    if (page.frameId === 0) return { allowed: true };
    // A frame without a known top page (the browser didn't say) gets nothing.
    const site = page.topOrigin && this.matcher.site(page.topOrigin);
    if (!site) return { allowed: false };
    if (this.matcher.sameSite(page.url, page.topOrigin!)) return { allowed: true };
    if ((await this.list()).some((a) => a.site === site && a.origin === page.origin)) return { allowed: true };
    return { allowed: false, ask: { frameHost: new URL(page.url).host, site } };
  }

  /** The user allowed this frame's origin on its top page's site, from the inline menu. */
  async approve(page: PageSender): Promise<boolean> {
    const access = await this.check(page);
    if (access.allowed) return true;
    if (!access.ask) return false;
    const approval: FrameApproval = { site: access.ask.site, origin: page.origin, approvedAt: new Date(this.now()).toISOString() };
    await this.store.set(KEY, [...(await this.list()), approval]);
    return true;
  }

  async remove(site: string, origin: string): Promise<void> {
    await this.store.set(KEY, (await this.list()).filter((a) => a.site !== site || a.origin !== origin));
  }
}
