import { CLOSE_UNAUTHORIZED, LiveConnection, reconnectDelay, websocketUrl, type LiveMessage } from './live';

class FakeSocket {
  static all: FakeSocket[] = [];
  readonly sent: unknown[] = [];
  closedWith: number | undefined;
  onopen: (() => void) | null = null;
  onmessage: ((event: { data: unknown }) => void) | null = null;
  onclose: ((event: { code: number }) => void) | null = null;

  constructor(readonly url: string) {
    FakeSocket.all.push(this);
  }

  send(data: string) {
    this.sent.push(JSON.parse(data));
  }

  close(code: number) {
    this.closedWith = code;
  }

  // Test controls: what the server would do.
  open() {
    this.onopen?.();
  }

  receive(message: unknown) {
    this.onmessage?.({ data: JSON.stringify(message) });
  }

  drop(code = 1006) {
    this.onclose?.({ code });
  }
}

const latest = () => FakeSocket.all.at(-1)!;
const flush = () => vi.advanceTimersByTimeAsync(0);

function connect(overrides: { accessToken?: (fresh: boolean) => Promise<string> } = {}) {
  const messages: LiveMessage[] = [];
  const connected = vi.fn();
  const accessToken = vi.fn(overrides.accessToken ?? (async (fresh: boolean) => (fresh ? 'fresh-token' : 'token')));
  const live = new LiveConnection({
    serverUrl: 'https://vault.example.com',
    accessToken,
    onMessage: (m) => messages.push(m),
    onConnected: connected,
    WebSocket: FakeSocket as unknown as typeof WebSocket,
    random: () => 0.5,
  });
  live.start();
  return { live, messages, connected, accessToken };
}

beforeEach(() => {
  FakeSocket.all = [];
  vi.useFakeTimers();
});
afterEach(() => vi.useRealTimers());

describe('websocketUrl', () => {
  it('maps the server origin to ws:// or wss:// on /v1/ws', () => {
    expect(websocketUrl('https://vault.example.com')).toBe('wss://vault.example.com/v1/ws');
    expect(websocketUrl('http://localhost:8080')).toBe('ws://localhost:8080/v1/ws');
  });
});

describe('reconnectDelay', () => {
  it('backs off exponentially with jitter, up to a minute', () => {
    expect(reconnectDelay(0, () => 0)).toBe(500);
    expect(reconnectDelay(0, () => 1)).toBe(1000);
    expect(reconnectDelay(3, () => 0.5)).toBe(6000);
    expect(reconnectDelay(20, () => 1)).toBe(60_000);
  });
});

describe('LiveConnection', () => {
  it('authenticates first, reports the connection, and passes notifications on', async () => {
    const { live, messages, connected } = connect();
    await flush();
    const socket = latest();
    expect(socket.url).toBe('wss://vault.example.com/v1/ws');
    socket.open();
    expect(socket.sent).toEqual([{ type: 'auth', accessToken: 'token' }]);
    expect(live.connected).toBe(false);

    socket.receive({ type: 'authenticated', expiresIn: 900 });
    expect(live.connected).toBe(true);
    expect(connected).toHaveBeenCalledTimes(1);
    socket.receive({ type: 'vault-changed', vaultId: 'v1', revision: 7 });
    socket.receive({ type: 'membership-changed', vaultId: 'v1' });
    expect(messages).toEqual([
      { type: 'vault-changed', vaultId: 'v1', revision: 7 },
      { type: 'membership-changed', vaultId: 'v1' },
    ]);
  });

  it('sends a fresh token a minute before the current one runs out', async () => {
    const { connected, accessToken } = connect();
    await flush();
    latest().open();
    latest().receive({ type: 'authenticated', expiresIn: 900 });
    await vi.advanceTimersByTimeAsync(839_000);
    expect(latest().sent).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(accessToken).toHaveBeenLastCalledWith(true);
    expect(latest().sent.at(-1)).toEqual({ type: 'auth', accessToken: 'fresh-token' });
    latest().receive({ type: 'authenticated', expiresIn: 900 });
    // Re-authentication is not a new connection.
    expect(connected).toHaveBeenCalledTimes(1);
  });

  it('reconnects with backoff, and with a fresh token after 4401', async () => {
    const { live, accessToken, connected } = connect();
    await flush();
    latest().drop(1006);
    expect(live.connected).toBe(false);
    await vi.advanceTimersByTimeAsync(749);
    expect(FakeSocket.all).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(FakeSocket.all).toHaveLength(2);
    expect(accessToken).toHaveBeenLastCalledWith(false);

    latest().drop(CLOSE_UNAUTHORIZED);
    await vi.advanceTimersByTimeAsync(1_500);
    expect(FakeSocket.all).toHaveLength(3);
    expect(accessToken).toHaveBeenLastCalledWith(true);

    // A successful sign-in resets the backoff.
    latest().open();
    latest().receive({ type: 'authenticated', expiresIn: 900 });
    expect(connected).toHaveBeenCalledTimes(1);
    latest().drop();
    await vi.advanceTimersByTimeAsync(750);
    expect(FakeSocket.all).toHaveLength(4);
  });

  it('keeps retrying while no token can be had, and stops for good when told', async () => {
    let offline = true;
    const { live } = connect({
      accessToken: async () => {
        if (offline) throw new Error('offline');
        return 'token';
      },
    });
    await vi.advanceTimersByTimeAsync(10_000);
    expect(FakeSocket.all).toHaveLength(0);
    offline = false;
    await vi.advanceTimersByTimeAsync(20_000);
    expect(FakeSocket.all).toHaveLength(1);

    live.stop();
    expect(latest().closedWith).toBe(1000);
    latest().drop(1000);
    await vi.advanceTimersByTimeAsync(120_000);
    expect(FakeSocket.all).toHaveLength(1);
  });

  it('ignores messages that aren’t JSON and sockets it has replaced', async () => {
    const { messages } = connect();
    await flush();
    const first = latest();
    first.onmessage?.({ data: 'not json' });
    first.drop();
    await vi.advanceTimersByTimeAsync(1_000);
    first.receive({ type: 'vault-changed', vaultId: 'old', revision: 1 });
    expect(messages).toEqual([]);
  });
});
