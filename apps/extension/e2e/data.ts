/** The test account's password; global-setup.ts creates the account and passes its email and Secret Key in the environment. */
export const PASSWORD = 'Lantern ruby quiet anchor 42';

/** A login saved for example.test. The test pages are served on *.test hosts mapped to 127.0.0.1. */
export const LOGIN = { title: 'Example shop', url: 'http://shop.example.test', username: 'maya@example.test', password: 'Xq7!plover-quartz-ochre-91' };

/**
 * The website icon account's logins (site-icons.spec.ts): a site with an icon, one without, and a
 * router address, which is never asked about. The server reaches the two sites' names on the test
 * pages through `OCTAPASS_DEV_ICON_HOSTS`.
 */
export const ICON_ITEMS = [
  { title: 'Icon shop', url: 'https://shop.octapass-e2e.com/login' },
  { title: 'Plain site', url: 'https://plain.octapass-e2e.net' },
  { title: 'Home router', url: 'http://192.168.1.1' },
];
export const ICON_HOSTS = ['octapass-e2e.com', 'www.octapass-e2e.com', 'octapass-e2e.net', 'www.octapass-e2e.net'];

/** A login for a sign-in form that shop.example.test embeds from another site (a cross-origin frame). */
export const FRAME_LOGIN = { title: 'Example accounts', url: 'http://accounts.idp.test', username: 'maya@idp.test', password: 'Vb2#lichen-harbor-cobalt-58' };

/** Two accounts on one website no step visits, which All items shows as one row. */
export const TEAM_LOGINS = [
  { title: 'Team admin', url: 'http://team.example.test', username: 'admin@team.example.test', password: 'Kd4$marsh-tundra-velvet-27' },
  { title: 'Team support', url: 'https://www.team.example.test/login', username: 'help@team.example.test', password: 'Rw9&cinder-plume-basalt-63' },
];

/**
 * The corpus runner's fixtures (tools/autofill-corpus/README.md), as real vault items for the
 * corpus pages' site. The identity model has no organization, so that one field stays empty.
 */
export const CORPUS_ITEMS = [
  {
    overview: { schemaVersion: 1 as const, title: 'Corpus login', type: 'login' as const, subtitle: 'alex@example.test', urls: ['http://corpus.test'] },
    details: { schemaVersion: 1 as const, username: 'alex@example.test', password: 'correct-horse-42!', totp: 'JBSWY3DPEHPK3PXP' },
  },
  {
    overview: { schemaVersion: 1 as const, title: 'Corpus card', type: 'card' as const },
    details: { schemaVersion: 1 as const, cardholder: 'Alex Doe', number: '4111111111111111', expiry: '09/29', cvv: '123' },
  },
  {
    overview: { schemaVersion: 1 as const, title: 'Corpus identity', type: 'identity' as const },
    details: {
      schemaVersion: 1 as const,
      firstName: 'Alex',
      lastName: 'Doe',
      email: 'alex@example.test',
      phone: '+15555550100',
      birthDate: '1990-04-12',
      address: { line1: '1 Test Street', line2: 'Apt 2', city: 'Springfield', region: 'CA', postalCode: '90210', country: 'US' },
    },
  },
];

/** The HTTP Basic sign-in on router.test (http-auth.spec.ts). */
export const ROUTER = { realm: 'Router admin', username: 'admin', password: 'router-pass-42' };
