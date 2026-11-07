import { fillIdle, fixPortDelivery, holdUntilAnswered } from './compat';

type Listener = (...args: never[]) => void;

function fakeEvent() {
  const listeners = new Set<Listener>();
  return {
    addListener: (listener: Listener) => void listeners.add(listener),
    removeListener: (listener: Listener) => void listeners.delete(listener),
    fire: (...args: unknown[]) => listeners.forEach((listener) => (listener as (...a: unknown[]) => void)(...args)),
  };
}

type FakePort = { onMessage: ReturnType<typeof fakeEvent> };

/** A runtime whose ports the worker sees through `fixPortDelivery`; `send` is the page posting. */
function connectThroughFix(onPort: (port: FakePort) => void, now = () => 0) {
  const onConnect = fakeEvent();
  fixPortDelivery(onConnect as never, now);
  onConnect.addListener(onPort as Listener);
  const raw: FakePort = { onMessage: fakeEvent() };
  onConnect.fire(raw);
  return { send: (message: unknown) => raw.onMessage.fire(message, raw) };
}

describe('fillIdle', () => {
  it('gives Safari an idle event that never fires', () => {
    const namespace: Parameters<typeof fillIdle>[0] = {};
    fillIdle(namespace);
    expect(() => namespace.idle!.onStateChanged.addListener(() => {})).not.toThrow();
  });

  it('keeps an idle API the browser has', () => {
    const idle = { onStateChanged: { addListener: vi.fn() } } as unknown as typeof chrome.idle;
    const namespace = { idle };
    fillIdle(namespace);
    expect(namespace.idle).toBe(idle);
  });
});

describe('fixPortDelivery', () => {
  it('replays messages that arrived before the worker listened on the port', () => {
    const received: unknown[] = [];
    let port!: FakePort;
    const page = connectThroughFix((p) => (port = p));

    page.send({ id: 1 });
    page.send({ id: 2 });
    port.onMessage.addListener(((message: unknown) => void received.push(message)) as Listener);
    page.send({ id: 3 });

    expect(received).toEqual([{ id: 1 }, { id: 2 }, { id: 3 }]);
  });

  it('drops a repeat from the first second, and keeps one after it', () => {
    let time = 0;
    const received: unknown[] = [];
    const page = connectThroughFix((port) => port.onMessage.addListener(((message: unknown) => void received.push(message)) as Listener), () => time);

    page.send({ id: 1, method: 'init' });
    page.send({ id: 1, method: 'init' });
    page.send({ id: 2, method: 'init' });
    time = 1000;
    page.send({ ping: true });
    page.send({ ping: true });

    expect(received).toEqual([{ id: 1, method: 'init' }, { id: 2, method: 'init' }, { ping: true }, { ping: true }]);
  });

  it('passes the port to every listener until it is removed', () => {
    const first = vi.fn();
    const second = vi.fn();
    let port!: FakePort;
    const page = connectThroughFix((p) => {
      port = p;
      p.onMessage.addListener(first);
      p.onMessage.addListener(second);
    });

    page.send({ id: 1 });
    port.onMessage.removeListener(second);
    page.send({ id: 2 });

    expect(first.mock.calls).toEqual([[{ id: 1 }, port], [{ id: 2 }, port]]);
    expect(second.mock.calls).toEqual([[{ id: 1 }, port]]);
  });
});

describe('holdUntilAnswered', () => {
  /** A runtime whose `connect` goes through `holdUntilAnswered`; `worker` is the worker's side. */
  function pageRuntime() {
    const posted: unknown[] = [];
    const worker = { onMessage: fakeEvent(), onDisconnect: fakeEvent() };
    const runtime = {
      connect: ({ name }: { name: string }) => ({ name, postMessage: (message: unknown) => void posted.push(message), ...worker }),
    };
    holdUntilAnswered(runtime as never, 'ui');
    return { connect: (name: string) => runtime.connect({ name }), worker, posted };
  }

  it("holds a page's messages until the worker has sent one", () => {
    const { connect, worker, posted } = pageRuntime();
    const port = connect('ui');

    port.postMessage({ id: 1 });
    port.postMessage({ id: 2 });
    expect(posted).toEqual([]);
    worker.onMessage.fire({ event: 'session' });
    port.postMessage({ id: 3 });

    expect(posted).toEqual([{ id: 1 }, { id: 2 }, { id: 3 }]);
  });

  it('drops what it holds when the port disconnects', () => {
    const { connect, worker, posted } = pageRuntime();
    const port = connect('ui');

    port.postMessage({ id: 1 });
    worker.onDisconnect.fire();
    worker.onMessage.fire({ event: 'session' });

    expect(posted).toEqual([]);
  });

  it('leaves other ports alone', () => {
    const { connect, posted } = pageRuntime();

    connect('passkey').postMessage({ id: 1 });

    expect(posted).toEqual([{ id: 1 }]);
  });
});
