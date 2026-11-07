import { uuidv7 } from '../ids';
import { generatePassword } from '../tools/generator';
import type { BackupCode, Item, ItemDetails, ItemOverview, Vault } from '../types';
import { SCHEMA_VERSION } from '../types';
import type { MockSharingData } from './MockSharing';

export interface VaultData {
  vaults: Vault[];
  items: Item[];
  /** Missing in vaults saved before sharing existed. */
  sharing?: MockSharingData;
}

const DAY = 86_400_000;

/** `Omit` that works per member of a union, so each details type keeps its own fields. */
type DistributiveOmit<T, K extends PropertyKey> = T extends unknown ? Omit<T, K> : never;

function strong(): string {
  return generatePassword({ kind: 'password', length: 20, uppercase: true, lowercase: true, digits: true, symbols: true, avoidAmbiguous: false });
}

function backupCodes(count: number, used: number): BackupCode[] {
  return Array.from({ length: count }, (_, i) => ({
    code: generatePassword({ kind: 'password', length: 8, uppercase: false, lowercase: true, digits: true, symbols: false, avoidAmbiguous: true }).replace(/^(.{4})/, '$1-'),
    used: i < used,
  }));
}

/** The demo vault every new mock account starts with: realistic data, including some health problems to fix. */
export function seedVault(email: string, now: number = Date.now()): VaultData {
  const name = email.split('@')[0]!;
  const personal: Vault = { id: uuidv7(now - 400 * DAY), name: 'Personal', type: 'personal', role: 'owner' };
  const family: Vault = {
    id: uuidv7(now - 380 * DAY),
    name: 'Family',
    type: 'family',
    role: 'owner',
    members: [
      { name: 'You', email, role: 'owner' },
      { name: 'Sam Rahman', email: 'sam.rahman@example.com', role: 'write' },
      { name: 'Leila Rahman', email: 'leila.rahman@example.com', role: 'write' },
    ],
  };
  const studio: Vault = {
    id: uuidv7(now - 200 * DAY),
    name: 'Studio',
    type: 'shared',
    role: 'manage',
    members: [
      { name: 'Jonas Weber', email: 'jonas@studio.example', role: 'owner' },
      { name: 'You', email, role: 'manage' },
      { name: 'Priya Natarajan', email: 'priya@studio.example', role: 'write' },
      { name: 'Contractor', email: 'alex.contractor@example.net', role: 'read' },
    ],
  };

  const items: Item[] = [];
  let age = 360;
  const add = (vault: Vault, overview: Omit<ItemOverview, 'schemaVersion'>, details: DistributiveOmit<ItemDetails, 'schemaVersion'>) => {
    const created = now - age * DAY;
    age -= 13;
    items.push({
      id: uuidv7(created),
      vaultId: vault.id,
      revision: 1,
      createdAt: new Date(created).toISOString(),
      updatedAt: new Date(created + 3 * DAY).toISOString(),
      overview: { schemaVersion: SCHEMA_VERSION, ...overview },
      details: { schemaVersion: SCHEMA_VERSION, ...details } as ItemDetails,
    });
  };
  const date = (daysAgo: number) => new Date(now - daysAgo * DAY).toISOString();
  const shared = strong();

  add(personal, { type: 'login', title: 'GitHub', subtitle: email, urls: ['https://github.com'], tags: ['work', 'developer'], favorite: true }, {
    username: email,
    password: strong(),
    totp: 'otpauth://totp/GitHub:' + encodeURIComponent(email) + '?secret=JBSWY3DPEHPK3PXP&issuer=GitHub',
    passkeys: [{ rpId: 'github.com', userName: name, createdAt: date(11) }],
    recovery: { email, twoFactorMethod: 'totp', backupCodes: backupCodes(10, 4) },
    passwordHistory: [{ password: strong(), changedAt: date(120) }],
  });
  add(personal, { type: 'login', title: 'Figma', subtitle: `${name}@studio.example`, urls: ['https://www.figma.com'], tags: ['work'], pinned: true }, {
    username: `${name}@studio.example`,
    password: strong(),
    totp: 'KRUGKIDROVUWG2ZAMJZG653OEBTG66BA',
    recovery: { email: `${name}@studio.example`, twoFactorMethod: 'totp' },
  });
  add(personal, { type: 'login', title: 'Google', subtitle: email, urls: ['https://accounts.google.com'], favorite: true }, {
    username: email,
    password: strong(),
    passkeys: [{ rpId: 'google.com', userName: email, createdAt: date(40) }],
    recovery: { phone: '+44 7700 900123', email: `${name}.backup@example.net`, twoFactorMethod: 'passkey', backupCodes: backupCodes(10, 1) },
  });
  add(personal, { type: 'login', title: 'Proton Mail', subtitle: `${name}@proton.example`, urls: ['https://account.proton.me'] }, {
    username: `${name}@proton.example`,
    password: generatePassword({ kind: 'passphrase', words: 6, separator: '-', capitalize: true, includeNumber: true }),
    totp: 'otpauth://totp/Proton:' + name + '?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Proton&digits=6&period=30',
    recovery: { phone: '+44 7700 900123', twoFactorMethod: 'totp' },
  });
  // The demo's own mailbox, without two-step sign-in: the recovery map flags it.
  add(personal, { type: 'login', title: 'Email', subtitle: email, urls: [`https://mail.${email.split('@')[1]}`] }, { username: email, password: strong(), recovery: { phone: '+44 7700 900123' } });
  add(personal, { type: 'login', title: 'Amazon', subtitle: email, urls: ['https://www.amazon.co.uk'] }, { username: email, password: shared });
  add(personal, { type: 'login', title: 'Etsy', subtitle: email, urls: ['https://www.etsy.com'] }, { username: email, password: shared, notes: 'Same password as Amazon. Change one of them.' });
  add(personal, { type: 'login', title: 'Dropbox', subtitle: email, urls: ['https://www.dropbox.com'] }, { username: email, password: 'dropbox2019', recovery: { twoFactorMethod: 'none' } });
  add(personal, { type: 'login', title: 'LinkedIn', subtitle: email, urls: ['https://www.linkedin.com'], tags: ['work'] }, { username: email, password: 'Summer2024!' });
  add(personal, { type: 'login', title: 'Slack', subtitle: `${name}@studio.example`, urls: ['https://studio-example.slack.com'], tags: ['work'] }, {
    username: `${name}@studio.example`,
    password: strong(),
    customFields: [{ label: 'Workspace', value: 'studio-example', hidden: false }],
  });
  add(personal, { type: 'login', title: 'AWS root', subtitle: 'API credential', urls: ['https://console.aws.amazon.com'], tags: ['work', 'developer'] }, {
    username: `aws@studio.example`,
    password: strong(),
    totp: 'otpauth://totp/AWS:root?secret=MFRGGZDFMZTWQ2LKNNWG23TPOBYXE43U&issuer=Amazon%20Web%20Services',
    customFields: [
      { label: 'Account ID', value: '4120 8833 1907', hidden: false },
      { label: 'Access key secret', value: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', hidden: true },
    ],
    recovery: { email: `aws@studio.example`, phone: '+44 7700 900456', twoFactorMethod: 'totp' },
  });
  add(personal, { type: 'login', title: 'Northwind Bank', subtitle: '••• 7781', urls: ['https://online.northwind-bank.example'] }, {
    username: '40017781',
    password: strong(),
    recovery: { phone: '+44 7700 900123', twoFactorMethod: 'sms' },
    notes: 'Telephone banking passcode is in the card item.',
  });
  add(personal, { type: 'login', title: 'Discord', subtitle: name, urls: ['https://discord.com'] }, {
    username: name,
    password: strong(),
    passkeys: [{ rpId: 'discord.com', userName: name, createdAt: date(70) }],
    recovery: { email, twoFactorMethod: 'passkey', backupCodes: backupCodes(8, 0) },
  });
  add(personal, { type: 'login', title: 'Duolingo', subtitle: email, urls: ['https://www.duolingo.com'] }, { username: email, password: 'qwerty123' });
  add(personal, { type: 'card', title: 'Travel card', subtitle: 'Visa ending 4242', favorite: true }, {
    cardholder: 'Maya Rahman',
    number: '4242 4242 4242 4242',
    expiry: '08/29',
    cvv: '123',
    pin: '4096',
    brand: 'Visa',
  });
  add(personal, { type: 'identity', title: 'Personal details', subtitle: 'Maya Rahman' }, {
    firstName: 'Maya',
    lastName: 'Rahman',
    email,
    phone: '+44 7700 900123',
    birthDate: '1991-04-17',
    address: { line1: '14 Elm Row', city: 'Edinburgh', postalCode: 'EH7 4AA', country: 'United Kingdom' },
  });
  add(personal, { type: 'secureNote', title: 'Passport', subtitle: 'Expires March 2031', tags: ['travel'] }, {
    notes: 'Passport number: 512 849 306\nIssued: 14 March 2021\nExpires: 13 March 2031\nPlace of issue: Glasgow',
  });
  add(personal, { type: 'password', title: 'Laptop disk encryption', subtitle: 'FileVault recovery key' }, {
    password: 'K7QF-2MXP-9RTA-L4WD-8HNE-3CJY',
    notes: 'Only needed if the login password is lost.',
  });

  add(family, { type: 'login', title: 'Netflix', subtitle: 'Family vault', urls: ['https://www.netflix.com'], favorite: true }, {
    username: 'family.rahman@example.com',
    password: 'Password123',
  });
  add(family, { type: 'login', title: 'Spotify', subtitle: 'family.rahman@example.com', urls: ['https://open.spotify.com'] }, {
    username: 'family.rahman@example.com',
    password: strong(),
  });
  add(family, { type: 'wifi', title: 'Home Wi-Fi', subtitle: 'Rahman-5G', tags: ['home'] }, {
    ssid: 'Rahman-5G',
    security: 'wpa2Wpa3',
    password: generatePassword({ kind: 'passphrase', words: 4, separator: '-', capitalize: false, includeNumber: true }),
  });
  add(family, { type: 'card', title: 'Groceries card', subtitle: 'Mastercard ending 5454' }, {
    cardholder: 'Sam Rahman',
    number: '5454 5454 5454 5454',
    expiry: '11/27',
    cvv: '321',
    brand: 'Mastercard',
  });
  add(family, { type: 'secureNote', title: 'Emergency contacts', tags: ['home'] }, {
    notes: 'GP surgery: 0131 496 0000\nSchool office: 0131 496 0123\nNeighbour (Iona): 07700 900789',
  });

  add(studio, { type: 'login', title: 'Studio Figma team', subtitle: 'design@studio.example', urls: ['https://www.figma.com'], tags: ['work'] }, {
    username: 'design@studio.example',
    password: strong(),
  });
  // Saved the way apps did before the Wi-Fi type: the vault moves it to one on unlock.
  add(studio, { type: 'password', title: 'Studio Wi-Fi', subtitle: 'Studio-Guest', tags: ['work'] }, {
    password: generatePassword({ kind: 'passphrase', words: 4, separator: '-', capitalize: false, includeNumber: true }),
    customFields: [{ label: 'SSID', value: 'Studio-Guest', hidden: false }],
  });

  return { vaults: [personal, family, studio], items, sharing: seedSharing(email, now, family) };
}

/** Devices, a family, emergency contacts both ways and their security log, for the sharing screens. */
function seedSharing(email: string, now: number, family: Vault): MockSharingData {
  const date = (daysAgo: number) => new Date(now - daysAgo * DAY).toISOString();
  // The mock recognises the user by email, so seeded people can have fixed ids.
  const me = 'acct-you';
  const contacts = {
    leila: { id: uuidv7(now - 90 * DAY), contactId: 'acct-leila', contactEmail: 'leila.rahman@example.com' },
    sam: { id: uuidv7(now - 60 * DAY), grantorId: 'acct-sam', grantorEmail: 'sam.rahman@example.com' },
  };
  const familyId = uuidv7(now - 380 * DAY);
  return {
    devices: [
      { id: uuidv7(now - 400 * DAY), name: 'This browser', platform: 'web', createdAt: date(400), lastSeenAt: date(0), current: true },
      { id: uuidv7(now - 220 * DAY), name: 'Maya’s iPhone', platform: 'ios', createdAt: date(220), lastSeenAt: date(0.1), current: false },
      { id: uuidv7(now - 35 * DAY), name: 'Firefox on Windows', platform: 'web', createdAt: date(35), lastSeenAt: date(9), current: false },
    ],
    family: {
      id: familyId,
      vaultId: family.id,
      organiserId: me,
      createdAt: date(380),
      members: [
        { accountId: me, email, role: 'organiser', joinedAt: date(380) },
        { accountId: 'acct-sam', email: 'sam.rahman@example.com', role: 'member', joinedAt: date(379) },
        { accountId: 'acct-leila', email: 'leila.rahman@example.com', role: 'member', joinedAt: date(300) },
      ],
      invites: [{ familyId, accountId: 'acct-omar', email: 'omar.rahman@example.com', organiserEmail: email, invitedAt: date(2) }],
    },
    invitations: [],
    emergency: {
      granted: [
        {
          ...contacts.leila,
          grantorId: me,
          grantorEmail: email,
          scope: { type: 'account' },
          accessLevel: 'view',
          waitDays: 7,
          status: 'requested',
          requestedAt: date(1),
          releasesAt: new Date(now + 6 * DAY).toISOString(),
          createdAt: date(90),
        },
      ],
      received: [
        { ...contacts.sam, contactId: me, contactEmail: email, scope: { type: 'account' }, accessLevel: 'view', waitDays: 3, status: 'released', requestedAt: date(5), releasesAt: date(2), releasedAt: date(2), createdAt: date(60) },
      ],
    },
    log: [
      { type: 'emergency-contact-added', createdAt: date(90), otherAccountEmail: contacts.leila.contactEmail, emergencyContactId: contacts.leila.id },
      { type: 'emergency-access-requested', createdAt: date(1), otherAccountEmail: contacts.leila.contactEmail, emergencyContactId: contacts.leila.id },
    ],
    verified: {},
  };
}
