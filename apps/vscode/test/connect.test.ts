// The client against a real HTTP server, on a real Unix socket and on loopback. The server applies
// the rules of the real one (apps/desktop/crates/connect/src/server.rs): the Host and Origin checks
// on loopback, the bearer token, and JSON with its Content-Type.

import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import * as http from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  ConnectClient,
  ConnectError,
  connectFolder,
  findEndpoint,
  parseEndpoint,
  type Endpoint,
  type Failure,
  type Place,
} from '../src/connect';

const TOKEN = 'opc1_test';

const ITEMS = {
  items: [
    {
      vault: 'Work',
      item: 'Stripe',
      itemId: '0192f0c8-1c2d-7a00-8000-0000000000aa',
      type: 'login',
      fields: [
        { name: 'username', secret: false },
        { name: 'password', secret: true },
      ],
    },
  ],
};

interface Seen {
  method?: string;
  url?: string;
  headers: http.IncomingHttpHeaders;
  body: string;
}

class FakeConnect {
  server!: http.Server;
  seen: Seen[] = [];
  /** Replaces every answer, for the failure cases. */
  override?: (response: http.ServerResponse, request: http.IncomingMessage) => void;
  hosts: string[] = [];
  aborted = false;

  async listen(where: string | number): Promise<void> {
    this.server = http.createServer((request, response) => {
      let body = '';
      request.on('data', (chunk) => (body += chunk));
      request.on('end', () => {
        this.seen.push({ method: request.method, url: request.url, headers: request.headers, body });
        this.answer(request, response, body);
      });
    });
    await new Promise<void>((resolve) => {
      if (typeof where === 'string') {
        this.server.listen(where, resolve);
      } else {
        this.server.listen(where, '127.0.0.1', resolve);
      }
    });
  }

  get port(): number {
    return (this.server.address() as AddressInfo).port;
  }

  close(): Promise<void> {
    this.server.closeAllConnections();
    return new Promise((resolve) => this.server.close(() => resolve()));
  }

  private answer(request: http.IncomingMessage, response: http.ServerResponse, body: string): void {
    const json = (status: number, value: unknown) => {
      response.writeHead(status, { 'Content-Type': 'application/json' });
      response.end(JSON.stringify(value));
    };
    const error = (status: number, code: string, message: string) => json(status, { error: { code, message } });
    if (this.hosts.length && (request.headers.origin || !this.hosts.includes(request.headers.host ?? ''))) {
      error(403, 'forbidden', 'Local programs only.');
      return;
    }
    if (this.override) {
      this.override(response, request);
      return;
    }
    const authorized = request.headers.authorization === `Bearer ${TOKEN}`;
    const route = `${request.method} ${request.url}`;
    if (route === 'GET /v1/status') {
      json(200, { unlocked: true });
    } else if (route === 'POST /v1/clients') {
      if (request.headers['content-type'] !== 'application/json') {
        response.writeHead(415, { 'Content-Type': 'text/plain' });
        response.end('Expected request with `Content-Type: application/json`');
        return;
      }
      const { name } = JSON.parse(body) as { name: string };
      if (!name) {
        error(400, 'bad-request', 'A client name is 1 to 64 characters.');
        return;
      }
      json(201, { id: 'kU2n6mN0Yk4', token: TOKEN, expiresAt: 1802592000 });
    } else if (!authorized) {
      error(401, 'unauthorized', 'No token.');
    } else if (route === 'GET /v1/items') {
      json(200, ITEMS);
    } else if (route === 'DELETE /v1/clients/self') {
      response.writeHead(204);
      response.end();
    } else {
      response.writeHead(404);
      response.end();
    }
  }
}

async function failureOf(call: Promise<unknown>): Promise<ConnectError> {
  const error = await call.then(
    () => undefined,
    (reason: unknown) => reason,
  );
  expect(error).toBeInstanceOf(ConnectError);
  return error as ConnectError;
}

let dir: string;

beforeAll(() => {
  // Not os.tmpdir() alone: a socket path has to fit in about 100 characters.
  dir = mkdtempSync(join(process.platform === 'win32' ? tmpdir() : '/tmp', 'op-'));
});

afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe.each([
  ['a Unix socket', 'socket'],
  ['loopback', 'loopback'],
] as const)('over %s', (_name, kind) => {
  let connect: FakeConnect;
  let endpoint: Endpoint;

  beforeEach(async () => {
    connect = new FakeConnect();
    if (kind === 'socket') {
      const path = join(dir, `connect-${Math.random().toString(36).slice(2)}.sock`);
      await connect.listen(path);
      endpoint = { kind: 'socket', path };
    } else {
      await connect.listen(0);
      connect.hosts = [`127.0.0.1:${connect.port}`, `localhost:${connect.port}`];
      endpoint = { kind: 'loopback', host: '127.0.0.1', port: connect.port };
    }
  });

  afterEach(() => connect.close());

  it('reads the status without a token', async () => {
    await expect(new ConnectClient(endpoint).status()).resolves.toEqual({ unlocked: true });
    expect(connect.seen[0]?.headers.authorization).toBeUndefined();
  });

  it('pairs with the name as JSON', async () => {
    const paired = await new ConnectClient(endpoint).pair('VS Code');
    expect(paired).toEqual({ id: 'kU2n6mN0Yk4', token: TOKEN, expiresAt: 1802592000 });
    const request = connect.seen[0]!;
    expect(JSON.parse(request.body)).toEqual({ name: 'VS Code' });
    expect(request.headers['content-type']).toBe('application/json');
  });

  it('lists names with the bearer token', async () => {
    await expect(new ConnectClient(endpoint, TOKEN).items()).resolves.toEqual(ITEMS.items);
    expect(connect.seen[0]?.headers.authorization).toBe(`Bearer ${TOKEN}`);
  });

  it('drops anything but names from a listing', async () => {
    connect.override = (response) => {
      const [first] = ITEMS.items;
      response.writeHead(200);
      response.end(JSON.stringify({ items: [{ ...first, value: 'hunter2', fields: [{ name: 'password', secret: true, value: 'hunter2' }] }] }));
    };
    const items = await new ConnectClient(endpoint, TOKEN).items();
    expect(JSON.stringify(items)).not.toContain('hunter2');
  });

  it('gives up the token', async () => {
    await expect(new ConnectClient(endpoint, TOKEN).forget()).resolves.toBeUndefined();
    expect(connect.seen[0]).toMatchObject({ method: 'DELETE', url: '/v1/clients/self' });
  });

  it('never sends an Origin header', async () => {
    await new ConnectClient(endpoint).status();
    expect(connect.seen[0]?.headers.origin).toBeUndefined();
  });

  it('answers 401 for a wrong or missing token', async () => {
    const error = await failureOf(new ConnectClient(endpoint, 'opc1_wrong').items());
    expect(error.failure).toBe('unauthorized');
    expect(error.status).toBe(401);
    expect((await failureOf(new ConnectClient(endpoint).items())).failure).toBe('unauthorized');
  });

  it.each<[number, string, Failure]>([
    [400, 'bad-request', 'bad-request'],
    [403, 'denied', 'denied'],
    [403, 'forbidden', 'forbidden'],
    [404, 'not-found', 'not-found'],
    [423, 'locked', 'locked'],
    [429, 'busy', 'busy'],
    [500, 'failed', 'failed'],
  ])('maps %i %s', async (status, code, failure) => {
    connect.override = (response) => {
      response.writeHead(status, { 'Content-Type': 'application/json' });
      response.end(JSON.stringify({ error: { code, message: 'From the server.' } }));
    };
    const error = await failureOf(new ConnectClient(endpoint, TOKEN).items());
    expect(error).toMatchObject({ failure, status, message: 'From the server.' });
  });

  it('copes with an error that has no JSON body', async () => {
    connect.override = (response) => {
      response.writeHead(423, { 'Content-Type': 'text/plain' });
      response.end('locked');
    };
    expect((await failureOf(new ConnectClient(endpoint, TOKEN).items())).failure).toBe('locked');
    connect.override = (response) => {
      response.writeHead(413);
      response.end();
    };
    expect((await failureOf(new ConnectClient(endpoint, TOKEN).items())).failure).toBe('failed');
  });

  it.each([
    ['not JSON', 'nope'],
    ['the wrong shape', '{"items":[{"vault":"Work"}]}'],
    ['not a list', '{"items":{}}'],
  ])('refuses a listing that is %s', async (_what, body) => {
    connect.override = (response) => {
      response.writeHead(200);
      response.end(body);
    };
    expect((await failureOf(new ConnectClient(endpoint, TOKEN).items())).failure).toBe('bad-response');
  });

  it('refuses an answer that is too big', async () => {
    connect.override = (response) => {
      response.writeHead(200);
      response.end(Buffer.alloc(9 * 1024 * 1024, 0x20));
    };
    expect((await failureOf(new ConnectClient(endpoint, TOKEN).items())).failure).toBe('bad-response');
  });

  it('stops waiting for approval when cancelled', async () => {
    connect.override = () => {};
    const stop = new AbortController();
    const waiting = new ConnectClient(endpoint).pair('VS Code', stop.signal);
    await new Promise((resolve) => setTimeout(resolve, 50));
    stop.abort();
    expect((await failureOf(waiting)).failure).toBe('cancelled');
  });

  it('says so when Connect goes away mid-answer', async () => {
    connect.override = (response) => {
      response.writeHead(200, { 'Content-Length': '1000' });
      response.write('{');
      setTimeout(() => response.destroy(), 10);
    };
    expect((await failureOf(new ConnectClient(endpoint, TOKEN).items())).failure).toBe('not-running');
  });
});

describe('the Host header', () => {
  it('names the address on loopback, and `localhost` when that was configured', async () => {
    const connect = new FakeConnect();
    await connect.listen(0);
    const { port } = connect;
    connect.hosts = [`127.0.0.1:${port}`, `localhost:${port}`];
    await new ConnectClient({ kind: 'loopback', host: '127.0.0.1', port }).status();
    await new ConnectClient({ kind: 'loopback', host: 'localhost', port }).status();
    expect(connect.seen.map(({ headers }) => headers.host)).toEqual([`127.0.0.1:${port}`, `localhost:${port}`]);
    await connect.close();
  });

  it('is rejected by a server that expects another port', async () => {
    const connect = new FakeConnect();
    await connect.listen(0);
    connect.hosts = ['127.0.0.1:1'];
    const error = await failureOf(new ConnectClient({ kind: 'loopback', host: '127.0.0.1', port: connect.port }).status());
    expect(error.failure).toBe('forbidden');
    await connect.close();
  });
});

describe('when nothing is listening', () => {
  it('reports it for a socket file nobody serves', async () => {
    const path = join(dir, 'stale.sock');
    const connect = new FakeConnect();
    await connect.listen(path);
    // Closing a Node server removes its socket file, so a plain file stands in for a stale one.
    await connect.close();
    writeFileSync(path, '');
    const error = await failureOf(new ConnectClient({ kind: 'socket', path }).status());
    expect(error.failure).toBe('not-running');
  });

  it('reports it for a closed port', async () => {
    const connect = new FakeConnect();
    await connect.listen(0);
    const { port } = connect;
    await connect.close();
    const error = await failureOf(new ConnectClient({ kind: 'loopback', host: '127.0.0.1', port }).status());
    expect(error.failure).toBe('not-running');
  });
});

describe('parseEndpoint', () => {
  it('reads what the docs allow', () => {
    expect(parseEndpoint('unix:/run/connect.sock')).toEqual({ kind: 'socket', path: '/run/connect.sock' });
    expect(parseEndpoint('http://127.0.0.1:8123')).toEqual({ kind: 'loopback', host: '127.0.0.1', port: 8123 });
    expect(parseEndpoint('http://127.0.0.1:8123/')).toEqual({ kind: 'loopback', host: '127.0.0.1', port: 8123 });
    expect(parseEndpoint('http://localhost:8123')).toEqual({ kind: 'loopback', host: 'localhost', port: 8123 });
  });

  it.each([
    'unix:',
    'http://example.com:8123',
    'https://127.0.0.1:8123',
    'http://127.0.0.1',
    'http://127.0.0.1:0',
    'http://127.0.0.1:70000',
    'http://127.0.0.1:80@example.com',
    'http://127.0.0.1:8123/v1',
    'http://localhost.example.com:8123',
    '127.0.0.1:8123',
  ])('refuses %s, so a token never leaves the machine', (text) => {
    expect(parseEndpoint(text)).toBeUndefined();
  });
});

describe('connectFolder', () => {
  it('follows the table in the docs', () => {
    expect(connectFolder({ env: {}, platform: 'darwin', home: '/Users/me' })).toBe(
      '/Users/me/Library/Application Support/com.octapass.connect',
    );
    expect(connectFolder({ env: {}, platform: 'linux', home: '/home/me' })).toBe(
      '/home/me/.local/share/com.octapass.connect',
    );
    expect(connectFolder({ env: { XDG_DATA_HOME: '/data' }, platform: 'linux', home: '/home/me' })).toBe(
      '/data/com.octapass.connect',
    );
    expect(connectFolder({ env: { XDG_DATA_HOME: 'relative' }, platform: 'linux', home: '/home/me' })).toBe(
      '/home/me/.local/share/com.octapass.connect',
    );
    expect(
      connectFolder({ env: { APPDATA: 'C:\\Users\\me\\AppData\\Roaming' }, platform: 'win32', home: 'C:\\Users\\me' }),
    ).toBe('C:\\Users\\me\\AppData\\Roaming\\com.octapass.connect');
  });
});

describe('findEndpoint', () => {
  let home: string;
  let folder: string;
  let place: Place;

  beforeEach(() => {
    home = mkdtempSync(join(dir, 'home-'));
    place = { env: { XDG_DATA_HOME: join(home, 'data') }, platform: 'linux', home };
    folder = connectFolder(place);
    mkdirSync(folder, { recursive: true });
    chmodSync(folder, 0o700);
  });

  it('takes OCTAPASS_CONNECT first, over a socket and a port file', () => {
    writeFileSync(join(folder, 'connect.sock'), '');
    writeFileSync(join(folder, 'connect.port'), '9000');
    const env = { ...place.env, OCTAPASS_CONNECT: 'http://127.0.0.1:1234' };
    expect(findEndpoint({ ...place, env })).toEqual({ kind: 'loopback', host: '127.0.0.1', port: 1234 });
  });

  it('ignores an empty OCTAPASS_CONNECT', () => {
    writeFileSync(join(folder, 'connect.port'), '9000');
    const env = { ...place.env, OCTAPASS_CONNECT: '' };
    expect(findEndpoint({ ...place, env })).toEqual({ kind: 'loopback', host: '127.0.0.1', port: 9000 });
  });

  it('stops at an OCTAPASS_CONNECT it can not read, as the CLI does', () => {
    writeFileSync(join(folder, 'connect.port'), '9000');
    const env = { ...place.env, OCTAPASS_CONNECT: 'http://example.com:9000' };
    expect(() => findEndpoint({ ...place, env })).toThrowError(expect.objectContaining({ failure: 'bad-endpoint' }));
  });

  it('takes the socket over the port file', () => {
    writeFileSync(join(folder, 'connect.sock'), '');
    writeFileSync(join(folder, 'connect.port'), '9000');
    expect(findEndpoint(place)).toEqual({ kind: 'socket', path: join(folder, 'connect.sock') });
  });

  it('reads the port file, with its line ending', () => {
    writeFileSync(join(folder, 'connect.port'), '9000\n');
    expect(findEndpoint(place)).toEqual({ kind: 'loopback', host: '127.0.0.1', port: 9000 });
  });

  it('says Connect is not running when there is neither', () => {
    expect(() => findEndpoint(place)).toThrowError(expect.objectContaining({ failure: 'not-running' }));
  });

  it('says Connect is not running for a port file that holds no port', () => {
    writeFileSync(join(folder, 'connect.port'), 'nonsense');
    expect(() => findEndpoint(place)).toThrowError(expect.objectContaining({ failure: 'not-running' }));
  });
});
