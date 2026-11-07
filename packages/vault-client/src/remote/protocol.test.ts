import { VaultError } from '../errors';
import type { VaultEngine } from './engine';
import { ApiProblem } from './http';
import { portClient, postEvents, serveEngine, type Port } from './protocol';

/** Two ends of a MessageChannel, typed as the bridge's ports. */
function channel(): [Port, Port] {
  const { port1, port2 } = new MessageChannel();
  port1.start();
  port2.start();
  return [port1 as unknown as Port, port2 as unknown as Port];
}

afterEach(() => vi.restoreAllMocks());

describe('the engine bridge', () => {
  it('forwards calls and results', async () => {
    const [page, worker] = channel();
    const engine = { listItems: vi.fn(async (filter: unknown) => [{ id: 'a', filter }]) } as unknown as VaultEngine;
    serveEngine(Promise.resolve(engine), worker);
    expect(await portClient(page).call('listItems', [{ query: 'git' }])).toEqual([{ id: 'a', filter: { query: 'git' } }]);
  });

  it('carries VaultError codes and normalises server problems', async () => {
    const [page, worker] = channel();
    const engine = {
      unlock: async () => {
        throw new VaultError('invalidCredentials');
      },
      sync: async () => {
        throw new ApiProblem(401, 'account-deleted', {});
      },
    } as unknown as VaultEngine;
    serveEngine(Promise.resolve(engine), worker);
    const client = portClient(page);
    await expect(client.call('unlock', ['pw'])).rejects.toMatchObject({ name: 'VaultError', code: 'invalidCredentials' });
    await expect(client.call('sync', [])).rejects.toBeInstanceOf(VaultError);
    await expect(client.call('sync', [])).rejects.toMatchObject({ code: 'accountDeleted' });
  });

  it('refuses methods outside the allowlist', async () => {
    const [page, worker] = channel();
    serveEngine(Promise.resolve({ loadCore: async () => 'secret' } as unknown as VaultEngine), worker);
    await expect(portClient(page).call('loadCore' as 'sync', [])).rejects.toThrow('Unknown method loadCore');
  });

  it('delivers engine events to the page', async () => {
    const [page, worker] = channel();
    const client = portClient(page);
    const received = new Promise((resolve) => client.onEvent(resolve));
    postEvents(worker)({ type: 'items' });
    expect(await received).toEqual({ type: 'items' });
  });
});
