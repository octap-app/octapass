import { serveRpc, type Handlers, type RpcResponse } from './rpc';
import { encodeWire } from './wire';

/** A port that, like Chrome's, drops messages nobody is listening for yet. */
function fakePort() {
  const listeners: ((message: unknown) => void)[] = [];
  const sent: RpcResponse[] = [];
  const port = {
    onMessage: { addListener: (listener: (message: unknown) => void) => listeners.push(listener) },
    postMessage: (message: RpcResponse) => sent.push(message),
  } as unknown as chrome.runtime.Port;
  const deliver = (message: unknown) => listeners.forEach((listener) => listener(message));
  return { port, sent, deliver };
}

describe('serveRpc', () => {
  it('answers requests that arrive while the worker is still starting', async () => {
    const { port, sent, deliver } = fakePort();
    let start!: (handlers: Handlers) => void;
    serveRpc(port, new Promise<Handlers>((resolve) => (start = resolve)));

    deliver({ id: 1, method: 'status', args: await encodeWire([]) });
    expect(sent).toEqual([]);

    start({ status: () => 'locked' });
    await vi.waitFor(() => expect(sent).toEqual([{ id: 1, ok: true, value: 'locked' }]));
  });

  it('reports unknown methods as errors', async () => {
    const { port, sent, deliver } = fakePort();
    serveRpc(port, {});
    deliver({ id: 2, method: 'nope', args: await encodeWire([]) });
    await vi.waitFor(() => expect(sent[0]).toMatchObject({ id: 2, ok: false }));
  });
});
