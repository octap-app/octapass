// Nearby against the real server: a place syncs as ciphertext only, and a second device works out
// the same Nearby list from it. `pnpm --filter @octapass/vault-client test:server`.

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { ItemDraft } from '../types';
import { device, eventually, PASSWORD, signedUp } from './testing/devices';
import { startServer, type TestServer } from './testing/server';

let server: TestServer;

beforeAll(async () => {
  server = await startServer();
});
afterAll(() => server?.stop());

/** Every file in the server's data directory (the database, its WAL), as raw bytes. */
function serverFiles(): Buffer {
  const files = readdirSync(server.dataDir, { recursive: true, withFileTypes: true }).filter((entry) => entry.isFile());
  return Buffer.concat(files.map((entry) => readFileSync(join(entry.parentPath, entry.name))));
}

// Distinctive values, so finding them anywhere in the server's files means they leaked.
const NAME = 'Zanzibar Lighthouse Studio';
const NETWORK = 'Quokka-Mesh-5G';
const NOTE = 'Spare key under the third flowerpot';
const LATITUDE = 12.345678;
const LONGITUDE = -98.765432;

describe('Nearby', () => {
  it('syncs a place as ciphertext only, and a second device lists it the same way', async () => {
    const first = await signedUp(server.url);
    const [vault] = await first.service.listVaults();
    const place = await first.service.saveItem({
      vaultId: vault!.id,
      overview: { schemaVersion: 1, type: 'place', title: NAME, place: { latitude: LATITUDE, longitude: LONGITUDE, radius: 200, networks: [NETWORK] } },
      details: { schemaVersion: 1, notes: NOTE },
    } as ItemDraft);
    await first.service.saveItem({
      vaultId: vault!.id,
      overview: { schemaVersion: 1, type: 'secureNote', title: 'Alarm code', places: [place.id] },
      details: { schemaVersion: 1, notes: '4821' },
    } as ItemDraft);

    const here = { networks: [NETWORK] };
    const listed = await first.service.nearby(here);
    expect(listed).toEqual([{ id: place.id, here: 'wifi', sections: [{ type: 'secureNote', items: [expect.any(String)] }] }]);

    // Another device of the same account gets the place and works out the same list.
    const second = await device();
    await second.service.signIn({ serverUrl: server.url, email: first.email, password: PASSWORD, secretKey: first.secretKey });
    await eventually(async () => expect(await second.service.nearby(here)).toEqual(listed));
    // So the server has it now, and keeps the place, and the link to it, only as ciphertext.
    const bytes = serverFiles();
    for (const secret of [NAME, NETWORK, NOTE, String(LATITUDE), String(LONGITUDE)]) {
      expect(bytes.includes(Buffer.from(secret)), `the server's files contain ${secret}`).toBe(false);
    }
    // By location this time: about 110 m north, within the 200 m radius.
    const near = await second.service.nearby({ position: { latitude: LATITUDE + 0.001, longitude: LONGITUDE, accuracy: 20 } });
    expect(near[0]).toMatchObject({ id: place.id, here: 'location' });
    expect(near[0]!.distance).toBeGreaterThan(100);
    expect(near[0]!.distance).toBeLessThan(120);
  });
});
