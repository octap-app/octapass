import { parseImport } from './index';

const EXPORT = {
  encrypted: false,
  folders: [{ id: 'f-work', name: 'Work' }],
  items: [
    {
      id: '1',
      organizationId: null,
      folderId: 'f-work',
      type: 1,
      reprompt: 0,
      name: 'GitHub',
      notes: 'Main account',
      favorite: true,
      fields: [
        { name: 'Recovery email', value: 'me@example.com', type: 0, linkedId: null },
        { name: 'PIN', value: '0000', type: 1, linkedId: null },
        { name: 'Admin', value: 'true', type: 2, linkedId: null },
        { name: 'Linked', value: null, type: 3, linkedId: 100 },
      ],
      login: {
        uris: [{ match: null, uri: 'https://github.com/login' }, { match: null, uri: 'https://gist.github.com' }],
        username: 'octocat',
        password: 'correct horse ',
        totp: 'otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP',
        fido2Credentials: [{ rpId: 'github.com' }],
      },
      collectionIds: null,
    },
    { id: '2', folderId: null, type: 2, name: 'Server notes', notes: 'ssh root@10.0.0.1', favorite: false, secureNote: { type: 0 } },
    {
      id: '3',
      folderId: null,
      type: 3,
      name: 'Visa',
      notes: null,
      favorite: false,
      card: { cardholderName: 'Ada Lovelace', brand: 'Visa', number: '4111 1111 1111 1111', expMonth: '4', expYear: '2029', code: '123' },
    },
    {
      id: '4',
      folderId: null,
      type: 4,
      name: 'Me',
      notes: 'Primary',
      favorite: false,
      identity: {
        title: 'Ms',
        firstName: 'Ada',
        middleName: null,
        lastName: 'Lovelace',
        address1: '12 St James Sq',
        address2: null,
        address3: null,
        city: 'London',
        state: null,
        postalCode: 'SW1Y 4JH',
        country: 'GB',
        company: 'Analytical Engines',
        email: 'ada@example.com',
        phone: '+44 20 7946 0000',
        ssn: null,
        username: null,
        passportNumber: '123456789',
        licenseNumber: null,
      },
    },
    { id: '5', type: 1, name: 'Empty login', login: { uris: [], username: null, password: null, totp: null } },
    { id: '6', type: 5, name: 'SSH key', sshKey: {} },
  ],
};

describe('parseImport bitwarden-json', () => {
  const result = parseImport('bitwarden-json', JSON.stringify(EXPORT));

  it('imports logins with URLs, one-time codes, custom fields and the folder as a tag', () => {
    expect(result.items[0]).toEqual({
      overview: {
        schemaVersion: 1,
        title: 'GitHub',
        type: 'login',
        urls: ['https://github.com/login', 'https://gist.github.com'],
        subtitle: 'octocat',
        tags: ['Work'],
        favorite: true,
      },
      details: {
        schemaVersion: 1,
        username: 'octocat',
        password: 'correct horse ',
        totp: 'otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP',
        notes: 'Main account',
        customFields: [
          { label: 'Recovery email', value: 'me@example.com', hidden: false },
          { label: 'PIN', value: '0000', hidden: true },
          { label: 'Admin', value: 'true', hidden: false },
        ],
      },
    });
  });

  it('imports secure notes, cards and identities', () => {
    expect(result.items.slice(1)).toEqual([
      {
        overview: { schemaVersion: 1, title: 'Server notes', type: 'secureNote' },
        details: { schemaVersion: 1, notes: 'ssh root@10.0.0.1' },
      },
      {
        overview: { schemaVersion: 1, title: 'Visa', type: 'card', subtitle: '•••• 1111' },
        details: { schemaVersion: 1, cardholder: 'Ada Lovelace', number: '4111 1111 1111 1111', expiry: '04/29', cvv: '123', brand: 'Visa' },
      },
      {
        overview: { schemaVersion: 1, title: 'Me', type: 'identity', subtitle: 'ada@example.com' },
        details: {
          schemaVersion: 1,
          firstName: 'Ada',
          lastName: 'Lovelace',
          email: 'ada@example.com',
          phone: '+44 20 7946 0000',
          address: { line1: '12 St James Sq', city: 'London', postalCode: 'SW1Y 4JH', country: 'GB' },
          notes: 'Company: Analytical Engines\nPassport number: 123456789\nPrimary',
        },
      },
    ]);
  });

  it('skips empty and unsupported items and warns about passkeys', () => {
    expect(result.skipped).toBe(2);
    expect(result.warnings).toEqual([
      'Item 5 skipped: no URL, username, password or notes.',
      "Item 6 skipped: this item type can't be imported yet.",
      "Passkeys can't be imported yet: 1 login was imported without one.",
    ]);
  });

  it('rejects encrypted exports with a hint', () => {
    for (const file of [{ encrypted: true, items: [] }, { encrypted: true, passwordProtected: true, data: 'x' }]) {
      expect(() => parseImport('bitwarden-json', JSON.stringify(file))).toThrow(
        expect.objectContaining({ code: 'invalidImportFile', message: expect.stringContaining('encrypted') }),
      );
    }
  });

  it.each(['name,url\n', '[]', '{"foo":1}', ''])('rejects %j', (text) => {
    expect(() => parseImport('bitwarden-json', text)).toThrow(expect.objectContaining({ code: 'invalidImportFile' }));
  });
});
