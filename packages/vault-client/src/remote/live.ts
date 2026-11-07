// Live change notifications on `GET /v1/ws` (docs/developers/sync-api.md, "Live notifications").
// The socket only says when to sync; it never carries item data. Missing a message costs nothing
// but latency: every (re)connect syncs, and the page's 30 s poll keeps running underneath.

export type LiveMessage =
  | { type: 'vault-changed'; vaultId: string; revision: number }
  | { type: 'membership-changed'; vaultId: string }
  | { type: 'session-revoked' }
  | { type: 'account-deleted' };

type ServerMessage = LiveMessage | { type: 'authenticated'; expiresIn: number };

export interface LiveOptions {
  serverUrl: string;
  /** A usable access token. With `fresh`, refresh it first: the server refused the last one, or it's about to run out. */
  accessToken: (fresh: boolean) => Promise<string>;
  onMessage: (message: LiveMessage) => void;
  /** Each time a connection is authenticated: catch up on whatever happened while there was none. */
  onConnected: () => void;
  WebSocket?: typeof WebSocket;
  random?: () => number;
}

/** Close code for a connection that isn't, or is no longer, authenticated. */
export const CLOSE_UNAUTHORIZED = 4401;
const RECONNECT_MIN_MS = 1_000;
const RECONNECT_MAX_MS = 60_000;
/** Send the next token this long before the current one expires. */
const REAUTH_MARGIN_S = 60;

export function websocketUrl(serverUrl: string): string {
  const url = new URL('/v1/ws', serverUrl);
  url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
  return url.href;
}

/** Exponential backoff with jitter, so a restarted server isn't hit by every client at once. */
export function reconnectDelay(attempt: number, random: () => number = Math.random): number {
  const ceiling = Math.min(RECONNECT_MAX_MS, RECONNECT_MIN_MS * 2 ** attempt);
  return ceiling / 2 + (random() * ceiling) / 2;
}

export class LiveConnection {
  private socket: WebSocket | undefined;
  private stopped = false;
  private attempt = 0;
  private authenticated = false;
  private retryTimer: ReturnType<typeof setTimeout> | undefined;
  private reauthTimer: ReturnType<typeof setTimeout> | undefined;

  constructor(private readonly options: LiveOptions) {}

  /** Whether notifications are flowing right now. */
  get connected(): boolean {
    return this.authenticated;
  }

  start(): void {
    void this.connect(false);
  }

  stop(): void {
    this.stopped = true;
    clearTimeout(this.retryTimer);
    clearTimeout(this.reauthTimer);
    const socket = this.socket;
    this.socket = undefined;
    this.authenticated = false;
    socket?.close(1000);
  }

  private async connect(fresh: boolean): Promise<void> {
    if (this.stopped) return;
    let token: string;
    try {
      token = await this.options.accessToken(fresh);
    } catch {
      // Offline, or the session is over; in that case the owner stops this connection.
      this.retry(fresh);
      return;
    }
    if (this.stopped) return;
    const Socket = this.options.WebSocket ?? WebSocket;
    let socket: WebSocket;
    try {
      socket = new Socket(websocketUrl(this.options.serverUrl));
    } catch {
      this.retry(false);
      return;
    }
    this.socket = socket;
    socket.onopen = () => socket.send(JSON.stringify({ type: 'auth', accessToken: token }));
    socket.onmessage = (event: MessageEvent) => this.receive(socket, event.data);
    socket.onclose = (event: CloseEvent) => this.closed(socket, event.code);
  }

  private receive(socket: WebSocket, data: unknown): void {
    if (socket !== this.socket || typeof data !== 'string') return;
    let message: ServerMessage;
    try {
      message = JSON.parse(data) as ServerMessage;
    } catch {
      return;
    }
    if (message.type !== 'authenticated') {
      this.options.onMessage(message);
      return;
    }
    const first = !this.authenticated;
    this.authenticated = true;
    this.attempt = 0;
    clearTimeout(this.reauthTimer);
    this.reauthTimer = setTimeout(() => void this.reauthenticate(socket), Math.max(0, message.expiresIn - REAUTH_MARGIN_S) * 1000);
    if (first) this.options.onConnected();
  }

  private async reauthenticate(socket: WebSocket): Promise<void> {
    try {
      const token = await this.options.accessToken(true);
      if (socket === this.socket) socket.send(JSON.stringify({ type: 'auth', accessToken: token }));
    } catch {
      // The server closes the connection when the old token runs out; reconnecting takes over.
    }
  }

  private closed(socket: WebSocket, code: number): void {
    if (socket !== this.socket) return;
    this.socket = undefined;
    this.authenticated = false;
    clearTimeout(this.reauthTimer);
    this.retry(code === CLOSE_UNAUTHORIZED);
  }

  private retry(fresh: boolean): void {
    if (this.stopped) return;
    clearTimeout(this.retryTimer);
    this.retryTimer = setTimeout(() => void this.connect(fresh), reconnectDelay(this.attempt++, this.options.random));
  }
}
