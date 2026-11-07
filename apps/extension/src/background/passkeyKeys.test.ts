import type { Item } from '@octapass/vault-client';
import { withoutPasskeyKeys, withPasskeyKeys } from './passkeyKeys';

const item: Item = {
  id: 'i1',
  vaultId: 'v1',
  revision: 3,
  createdAt: '2026-10-24T00:00:00Z',
  updatedAt: '2026-10-24T00:00:00Z',
  overview: { schemaVersion: 1, title: 'Example', type: 'login' },
  details: {
    schemaVersion: 1,
    username: 'maya',
    passkeys: [
      { rpId: 'example.com', userName: 'maya', createdAt: '2026-10-24T00:00:00Z', credentialId: 'c1', privateKey: 'secret-1' },
      { rpId: 'example.com', userName: 'old', createdAt: '2026-10-01T00:00:00Z', credentialId: 'c2', privateKey: 'secret-2' },
    ],
  } as Item['details'],
};

describe('passkey keys', () => {
  it('leaves the keys out of what pages see', () => {
    const shown = withoutPasskeyKeys(item);
    expect(JSON.stringify(shown)).not.toContain('secret-');
    expect((shown.details as { passkeys: unknown[] }).passkeys).toEqual([
      { rpId: 'example.com', userName: 'maya', createdAt: '2026-10-24T00:00:00Z', credentialId: 'c1' },
      { rpId: 'example.com', userName: 'old', createdAt: '2026-10-01T00:00:00Z', credentialId: 'c2' },
    ]);
  });

  it('puts the keys back for the passkeys a save keeps, and drops removed ones', () => {
    const edited = withoutPasskeyKeys(item);
    const draft = { ...edited, details: { ...edited.details, passkeys: [(edited.details as { passkeys: unknown[] }).passkeys[0]] } as Item['details'] };
    const saved = withPasskeyKeys(draft, item);
    expect((saved.details as { passkeys: unknown[] }).passkeys).toEqual([
      { rpId: 'example.com', userName: 'maya', createdAt: '2026-10-24T00:00:00Z', credentialId: 'c1', privateKey: 'secret-1' },
    ]);
  });

  it('never moves a key to another credential or another site', () => {
    const draft = {
      ...item,
      details: {
        schemaVersion: 1,
        passkeys: [
          { rpId: 'example.com', userName: 'x', createdAt: '', credentialId: 'c9' },
          { rpId: 'evil.com', userName: 'x', createdAt: '', credentialId: 'c1' },
        ],
      } as Item['details'],
    };
    expect(JSON.stringify(withPasskeyKeys(draft, item))).not.toContain('secret-');
  });
});
