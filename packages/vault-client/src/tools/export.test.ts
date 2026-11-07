import type { Item, Vault } from '../types';
import { parseCsv } from './csv';
import { exportCsv, exportJson } from './export';

const vaults: Vault[] = [
  { id: 'v1', name: 'Personal', type: 'personal', role: 'owner' },
  { id: 'v2', name: 'Family', type: 'shared', role: 'write', members: [{ name: 'Sam', email: 's@example.com', role: 'write' }] },
];

const base = { revision: 3, createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-02-01T00:00:00.000Z' };

const items: Item[] = [
  {
    ...base,
    id: 'i1',
    vaultId: 'v1',
    overview: { schemaVersion: 1, title: 'GitHub', type: 'login', urls: ['https://github.com', 'https://gist.github.com'], tags: ['dev', 'work'], favorite: true, subtitle: 'octocat' },
    details: {
      schemaVersion: 1,
      username: 'octocat',
      password: 'p,"w"',
      totp: 'otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP',
      notes: 'Main account',
      customFields: [{ label: 'PIN', value: '1234', hidden: true }],
    },
  },
  {
    ...base,
    id: 'i2',
    vaultId: 'v2',
    overview: { schemaVersion: 1, title: 'Visa', type: 'card' },
    details: { schemaVersion: 1, cardholder: 'Sam Doe', number: '4111111111111111', expiry: '04/29', cvv: '123', notes: 'Joint card' },
  },
  {
    ...base,
    id: 'i3',
    vaultId: 'v1',
    overview: { schemaVersion: 1, title: 'Me', type: 'identity' },
    details: { schemaVersion: 1, firstName: 'Sam', lastName: 'Doe', email: 'sam@example.com', address: { line1: '1 Main St', city: 'Springfield', postalCode: '12345', country: 'US' } },
  },
  {
    ...base,
    id: 'i4',
    vaultId: 'v1',
    overview: { schemaVersion: 1, title: 'Wi-Fi', type: 'secureNote' },
    details: { schemaVersion: 1, notes: 'SSID: home\nKey: secret' },
  },
  {
    ...base,
    id: 'i5',
    vaultId: 'v1',
    overview: { schemaVersion: 1, title: 'Shop API (production)', type: 'environment', subtitle: 'Shop API · production' },
    details: {
      schemaVersion: 1,
      project: 'shop-api',
      projectName: 'Shop API',
      stage: 'production',
      variables: [
        { key: 'DATABASE_URL', value: 'postgres://db', concealed: true },
        { key: 'PORT', value: '8080', concealed: false },
        { key: 'EMPTY', value: '', concealed: false },
      ],
      notes: 'Prod env',
    },
  },
];

describe('exportJson', () => {
  it('writes the versioned format with whole overviews and details', () => {
    const withUnknown = { ...items[0]!, overview: { ...items[0]!.overview, futureField: 1 } } as Item;
    const json = exportJson(vaults, [withUnknown], new Date('2026-10-23T00:00:00.000Z'));
    expect(json).toContain('\n  "format"');
    expect(JSON.parse(json)).toEqual({
      format: 'octapass-export',
      version: 1,
      exportedAt: '2026-10-23T00:00:00.000Z',
      vaults: [
        { id: 'v1', name: 'Personal', type: 'personal' },
        { id: 'v2', name: 'Family', type: 'shared' },
      ],
      items: [
        {
          id: 'i1',
          vaultId: 'v1',
          createdAt: base.createdAt,
          updatedAt: base.updatedAt,
          overview: withUnknown.overview,
          details: withUnknown.details,
        },
      ],
    });
  });
});

describe('exporting documents', () => {
  const document: Item = {
    ...base,
    id: 'i5',
    vaultId: 'v1',
    overview: { schemaVersion: 1, title: 'Lease', type: 'document' },
    details: { schemaVersion: 1, notes: 'Signed', attachments: [{ id: 'f1', name: 'lease.pdf', type: 'application/pdf', size: 1200, key: 'wrapped' }] },
  };

  it('lists files by name, type and size, without their keys', () => {
    const [exported] = JSON.parse(exportJson(vaults, [document])).items;
    expect(exported.details.attachments).toEqual([{ id: 'f1', name: 'lease.pdf', type: 'application/pdf', size: 1200 }]);
    const [, row] = parseCsv(exportCsv(vaults, [document]));
    expect(row!.slice(1, 3)).toEqual(['document', 'Lease']);
    expect(row![7]).toBe('File: lease.pdf\nSigned');
  });
});

describe('exportCsv', () => {
  const rows = parseCsv(exportCsv(vaults, items));

  it('writes the header and one row per item', () => {
    expect(rows[0]).toEqual(['vault', 'type', 'title', 'url', 'username', 'password', 'totp', 'notes', 'tags', 'favorite']);
    expect(rows).toHaveLength(6);
  });

  it('writes logins with joined URLs and tags, custom fields in the notes', () => {
    expect(rows[1]).toEqual([
      'Personal',
      'login',
      'GitHub',
      'https://github.com https://gist.github.com',
      'octocat',
      'p,"w"',
      'otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP',
      'PIN: 1234\nMain account',
      'dev,work',
      'true',
    ]);
  });

  it('summarises cards and identities in the notes', () => {
    expect(rows[2]![7]).toBe('Cardholder: Sam Doe\nNumber: 4111111111111111\nExpiry: 04/29\nCVV: 123\nJoint card');
    expect(rows[3]![7]).toBe('Name: Sam Doe\nEmail: sam@example.com\nAddress: 1 Main St, 12345 Springfield, US');
    expect(rows[2]!.slice(0, 3)).toEqual(['Family', 'card', 'Visa']);
  });

  it('writes secure notes as notes', () => {
    expect(rows[4]).toEqual(['Personal', 'secureNote', 'Wi-Fi', '', '', '', '', 'SSID: home\nKey: secret', '', 'false']);
  });

  it('writes environments with their project, stage and variables in the notes', () => {
    expect(rows[5]!.slice(0, 3)).toEqual(['Personal', 'environment', 'Shop API (production)']);
    expect(rows[5]![7]).toBe('Project: shop-api\nStage: production\nDATABASE_URL: postgres://db\nPORT: 8080\nProd env');
  });

  it('keeps an API credential’s key in the notes', () => {
    const key: Item = { ...base, id: 'k', vaultId: 'v1', overview: { schemaVersion: 1, title: 'GitHub', type: 'apiCredential', urls: ['https://dev.example'] }, details: { schemaVersion: 1, credential: 'FAKE-key', hostname: 'dev.example' } };
    const [, row] = parseCsv(exportCsv(vaults, [key]));
    expect(row![7]).toBe('Key: FAKE-key\nHost: dev.example');
  });

  it('leaves masked email provider tokens to the JSON export', () => {
    const provider: Item = { ...base, id: 'p1', vaultId: 'v1', overview: { schemaVersion: 1, title: 'addy.io', type: 'maskedEmailProvider' }, details: { schemaVersion: 1, provider: 'addy', token: 'tok', domain: 'anonaddy.me' } };
    expect(parseCsv(exportCsv(vaults, [...items, provider]))).toHaveLength(6);
    expect(JSON.parse(exportJson(vaults, [provider])).items[0].details.token).toBe('tok');
  });
});
