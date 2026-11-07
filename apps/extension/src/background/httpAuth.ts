// HTTP Basic and Digest sign-in prompts (plan 05). They have no form for the content script to
// fill, so the browser asks the background (`webRequest.onAuthRequired`) and waits for the answer.
// Stricter than ordinary autofill: only logins for the request's exact origin (and its realm, when
// the login has one), only while the vault is unlocked, and only after the user allowed the site
// once in a small Octa Pass window. Requests other than a top-level page load get nothing unless
// the page in the tab, and whatever started the request, are that same origin, so a page can't
// sign itself in to another site through a frame, an image or a fetch. Proxies get nothing, and
// neither does a request whose credentials were already turned down: the browser asks instead.
// Approvals live in the background's own IndexedDB, and the settings list them.

import type { Item, ItemSummary, LoginDetails } from '@octapass/vault-client';
import type { KeyValueStore } from './storage';

const KEY = 'httpAuthApprovals';
/** How long a prompt waits for the user before the browser's own sign-in dialog takes over. */
export const PROMPT_TIMEOUT_MS = 2 * 60_000;
/** Request ids already answered, so wrong credentials aren't sent again and again. */
const MAX_ANSWERED = 200;

/** What the browser reports about a challenge: Chrome's and Firefox's `onAuthRequired` details. */
export interface AuthChallenge {
  requestId: string;
  url: string;
  realm?: string;
  scheme?: string;
  isProxy?: boolean;
  /** `main_frame` for a top-level page load. */
  type?: string;
  /** Chrome: the origin that started the request. */
  initiator?: string;
  /** Firefox: the URL that started the request. */
  originUrl?: string;
  /** The origin of the page in the tab, looked up by the caller. */
  topOrigin?: string;
}

export interface AuthCredentials {
  username: string;
  password: string;
}

/** The answer for `onAuthRequired`: empty lets the browser show its own dialog. */
export type AuthAnswer = { authCredentials?: AuthCredentials };

/** A site the user allowed, and the login they picked for it. */
export interface HttpAuthApproval {
  origin: string;
  itemId: string;
  approvedAt: string;
}

/** What the prompt window shows. Never a password. */
export interface HttpAuthPrompt {
  origin: string;
  realm?: string;
  logins: { itemId: string; title: string; username: string }[];
}

export interface HttpAuthHost {
  readonly unlocked: boolean;
  listItems(): Promise<ItemSummary[]>;
  getItem(id: string): Promise<Item>;
}

export interface HttpAuthOptions {
  /** Opens the prompt window for a request; returns the window's id. */
  openPrompt(id: string): Promise<number | undefined>;
  /** Closes it once answered. */
  closePrompt?(windowId: number): Promise<void>;
  /** Keeps the background running while a prompt waits (Chrome stops an idle worker). */
  busy?(waiting: boolean): void;
  now?: () => number;
  newId?: () => string;
  timeoutMs?: number;
}

interface Pending {
  origin: string;
  realm?: string;
  logins: { item: Item; details: LoginDetails }[];
  windowId?: number;
  timer: ReturnType<typeof setTimeout>;
  settle(itemId: string | undefined): void;
  answer: Promise<string | undefined>;
}

const originOf = (url: string): string | undefined => {
  try {
    const parsed = new URL(url);
    return /^https?:$/.test(parsed.protocol) ? parsed.origin : undefined;
  } catch {
    return undefined;
  }
};

export class HttpAuth {
  private readonly pending = new Map<string, Pending>();
  private readonly answered: string[] = [];
  /** Sites where the user said "Not now" since the browser started: no new window for them. */
  private readonly declined = new Set<string>();

  constructor(
    private readonly host: HttpAuthHost,
    private readonly store: KeyValueStore,
    private readonly options: HttpAuthOptions,
  ) {}

  async answer(challenge: AuthChallenge): Promise<AuthAnswer> {
    const origin = this.fillableOrigin(challenge);
    if (!origin || !this.host.unlocked || this.answered.includes(challenge.requestId)) return {};
    const logins = await this.candidates(origin, challenge.realm);
    if (!logins.length) return {};
    const approval = (await this.approvals()).find((a) => a.origin === origin);
    let itemId: string | undefined;
    if (approval) itemId = (logins.find((l) => l.item.id === approval.itemId) ?? logins[0]!).item.id;
    else if (!this.declined.has(origin)) itemId = await this.ask(origin, challenge.realm, logins);
    if (!itemId || !this.host.unlocked) return {};
    const details = (await this.host.getItem(itemId)).details as LoginDetails;
    this.answered.push(challenge.requestId);
    if (this.answered.length > MAX_ANSWERED) this.answered.shift();
    return { authCredentials: { username: details.username ?? '', password: details.password ?? '' } };
  }

  /** For the prompt window. */
  prompt(id: string): HttpAuthPrompt {
    const pending = this.requirePending(id);
    return {
      origin: pending.origin,
      ...(pending.realm ? { realm: pending.realm } : {}),
      logins: pending.logins.map(({ item, details }) => ({ itemId: item.id, title: item.overview.title, username: details.username ?? '' })),
    };
  }

  /** "Sign in": remembers the site and the login, and answers the waiting request. */
  async approve(id: string, itemId: string): Promise<void> {
    const pending = this.requirePending(id);
    if (!pending.logins.some((l) => l.item.id === itemId)) throw new Error('That login isn’t for this site.');
    const approval: HttpAuthApproval = { origin: pending.origin, itemId, approvedAt: new Date((this.options.now ?? Date.now)()).toISOString() };
    await this.store.set(KEY, [...(await this.approvals()).filter((a) => a.origin !== pending.origin), approval]);
    pending.settle(itemId);
  }

  /** "Not now", or the window was closed: the browser shows its own dialog. */
  decline(id: string): void {
    const pending = this.pending.get(id);
    if (!pending) return;
    this.declined.add(pending.origin);
    pending.settle(undefined);
  }

  windowClosed(windowId: number): void {
    for (const [id, pending] of this.pending) if (pending.windowId === windowId) this.decline(id);
  }

  /** Locking answers every waiting prompt with nothing. */
  cancelAll(): void {
    for (const pending of this.pending.values()) pending.settle(undefined);
  }

  async approvals(): Promise<HttpAuthApproval[]> {
    return (await this.store.get<HttpAuthApproval[]>(KEY)) ?? [];
  }

  async remove(origin: string): Promise<void> {
    await this.store.set(KEY, (await this.approvals()).filter((a) => a.origin !== origin));
    this.declined.delete(origin);
  }

  /** The request's origin, when Octa Pass may answer it at all. */
  private fillableOrigin(challenge: AuthChallenge): string | undefined {
    if (challenge.isProxy) return undefined;
    if (challenge.scheme && !/^(basic|digest)$/i.test(challenge.scheme)) return undefined;
    const origin = originOf(challenge.url);
    if (!origin || challenge.type === 'main_frame') return origin;
    const source = challenge.initiator ?? challenge.originUrl;
    const sameOrigin = (url: string | undefined) => url !== undefined && originOf(url) === origin;
    return sameOrigin(challenge.topOrigin) && sameOrigin(source) ? origin : undefined;
  }

  /** Logins for the exact origin: those with the challenge's realm first, then those without one. */
  private async candidates(origin: string, realm: string | undefined): Promise<Pending['logins']> {
    const summaries = (await this.host.listItems()).filter((s) => s.type === 'login' && !s.deletedAt && s.urls?.some((url) => originOf(url) === origin));
    const logins: Pending['logins'] = [];
    for (const summary of summaries) {
      const item = await this.host.getItem(summary.id);
      const details = item.details as LoginDetails;
      if (!details.password) continue;
      if (details.httpRealm && details.httpRealm !== (realm ?? '')) continue;
      logins.push({ item, details });
    }
    return logins.sort((a, b) => Number(!a.details.httpRealm) - Number(!b.details.httpRealm));
  }

  /** One window per site at a time: other requests for it wait for the same answer. */
  private ask(origin: string, realm: string | undefined, logins: Pending['logins']): Promise<string | undefined> {
    for (const pending of this.pending.values()) if (pending.origin === origin) return pending.answer;
    const id = (this.options.newId ?? (() => crypto.randomUUID()))();
    let settle!: (itemId: string | undefined) => void;
    const answer = new Promise<string | undefined>((resolve) => {
      settle = (itemId) => {
        const pending = this.pending.get(id);
        if (!pending) return;
        clearTimeout(pending.timer);
        this.pending.delete(id);
        if (!this.pending.size) this.options.busy?.(false);
        if (pending.windowId !== undefined) void this.options.closePrompt?.(pending.windowId).catch(() => {});
        resolve(itemId);
      };
    });
    const timer = setTimeout(() => settle(undefined), this.options.timeoutMs ?? PROMPT_TIMEOUT_MS);
    const pending: Pending = { origin, ...(realm ? { realm } : {}), logins, timer, settle, answer };
    this.pending.set(id, pending);
    this.options.busy?.(true);
    this.options.openPrompt(id).then(
      (windowId) => {
        if (windowId !== undefined && this.pending.has(id)) pending.windowId = windowId;
      },
      () => settle(undefined),
    );
    return answer;
  }

  private requirePending(id: string): Pending {
    const pending = this.pending.get(id);
    if (!pending) throw new Error('This sign-in request has ended.');
    return pending;
  }
}
