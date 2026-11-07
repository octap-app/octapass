// What the shared service worker expects from the browser and Safari's WebKit doesn't do.
//
// - Safari has no `chrome.idle`, so the worker's listener gets an event that never fires: "Lock when
//   the computer locks" has no effect there, and the inactivity timer still locks the vault.
// - Ports: WebKit drops messages that reach the worker before it listens on the port, and delivers
//   messages posted before the port finished connecting twice. Pages post their first call right
//   after connecting (the popup's `init`, a passkey request), and the worker listens once the vault
//   has loaded. So each port holds its messages until its first listener, and drops a message that
//   repeats one from the port's first second (RPC ids never repeat on a port; pings carry nothing).
// - WebKit also loses a message posted right after connecting when that connect had to start the
//   worker, as when the popup opens after Safari stopped an idle worker. The worker sends the
//   session state on a UI port as soon as it listens, so pages hold what they post on one until then.

export type Idle = Pick<typeof chrome.idle, 'onStateChanged'>;
type MessageListener = (message: unknown, port: Port) => void;
type MessageEvent = { addListener(listener: MessageListener): void; removeListener(listener: MessageListener): void };
type Port = { onMessage: MessageEvent };
export type ConnectEvent = { addListener(listener: (port: Port) => void): void };
type PagePort = Port & { name: string; postMessage(message: unknown): void; onDisconnect: { addListener(listener: () => void): void } };
export type Connect = { connect(...args: never[]): PagePort };

const REPEAT_WINDOW_MS = 1000;

export function fillIdle(namespace: { idle?: Idle }): void {
  namespace.idle ??= { onStateChanged: { addListener() {} } as unknown as typeof chrome.idle.onStateChanged };
}

export function fixPortDelivery(onConnect: ConnectEvent, now = Date.now): void {
  const addListener = onConnect.addListener.bind(onConnect);
  onConnect.addListener = (listener) => addListener((port) => listener(deliverOnce(port, now)));
}

function deliverOnce(port: Port, now: () => number): Port {
  const listeners = new Set<MessageListener>();
  const queued: unknown[] = [];
  let seen: Set<string> | undefined = new Set();
  const connectedAt = now();
  const event = port.onMessage;

  event.addListener((message) => {
    if (seen && now() - connectedAt >= REPEAT_WINDOW_MS) seen = undefined;
    if (seen) {
      const key = JSON.stringify(message);
      if (seen.has(key)) return;
      seen.add(key);
    }
    if (listeners.size === 0) queued.push(message);
    for (const listener of listeners) listener(message, port);
  });
  event.addListener = (listener) => {
    listeners.add(listener);
    for (const message of queued.splice(0)) listener(message, port);
  };
  event.removeListener = (listener) => void listeners.delete(listener);
  return port;
}

/** Page side: a port named `name` posts nothing until the worker has sent something on it. */
export function holdUntilAnswered(runtime: Connect, name: string): void {
  const connect = runtime.connect.bind(runtime);
  runtime.connect = (...args) => {
    const port = connect(...args);
    if (port.name !== name) return port;
    let held: unknown[] | undefined = [];
    const post = port.postMessage.bind(port);
    port.onMessage.addListener(() => {
      const messages = held ?? [];
      held = undefined;
      for (const message of messages) post(message);
    });
    port.onDisconnect.addListener(() => (held = undefined));
    port.postMessage = (message) => void (held ? held.push(message) : post(message));
    return port;
  };
}
