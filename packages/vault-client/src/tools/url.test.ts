import { hostnameOf, registrableDomain } from './url';
import { changePasswordUrl, hasWebsite, insecureUrl, isLocalHost, sameWebsite, uniqueWebsites, withUniqueWebsites } from './url';

describe('hostnameOf', () => {
  it.each([
    ['https://github.com/login', 'github.com'],
    ['github.com/login', 'github.com'],
    ['  WWW.Example.COM  ', 'example.com'],
    ['http://user:pw@sub.example.org:8080/x?y#z', 'sub.example.org'],
    ['example.com.', 'example.com'],
    ['android://hash@com.example.app/', 'com.example.app'],
    ['http://192.168.1.1/admin', '192.168.1.1'],
    ['example.com:8443/app', 'example.com'],
  ])('reads %j as %j', (input, expected) => {
    expect(hostnameOf(input)).toBe(expected);
  });

  it.each(['', '   ', 'not a url', 'mailto:alice@example.com', 'https://'])('returns undefined for %j', (input) => {
    expect(hostnameOf(input)).toBeUndefined();
  });
});

describe('registrableDomain', () => {
  it.each([
    ['accounts.google.com', 'google.com'],
    ['google.com', 'google.com'],
    ['aws.amazon.com', 'amazon.com'],
    ['www.bbc.co.uk', 'bbc.co.uk'],
    ['bbc.co.uk', 'bbc.co.uk'],
    ['shop.example.com.au', 'example.com.au'],
    ['localhost', 'localhost'],
    ['10.0.0.1', '10.0.0.1'],
    ['Login.Microsoft.com.', 'microsoft.com'],
  ])('reduces %j to %j', (input, expected) => {
    expect(registrableDomain(input)).toBe(expected);
  });
});

describe('changePasswordUrl', () => {
  it('uses the first website, always https on the internet', () => {
    expect(changePasswordUrl(['https://accounts.example.com/signin'])).toBe('https://accounts.example.com/.well-known/change-password');
    expect(changePasswordUrl(['http://example.com'])).toBe('https://example.com/.well-known/change-password');
    expect(changePasswordUrl(['example.com:8443/x'])).toBe('https://example.com:8443/.well-known/change-password');
    expect(changePasswordUrl(['mailto:a@b.c', 'example.org'])).toBe('https://example.org/.well-known/change-password');
  });
  it('keeps http on the local network, and refuses other schemes', () => {
    expect(changePasswordUrl(['http://192.168.1.1/admin'])).toBe('http://192.168.1.1/.well-known/change-password');
    expect(changePasswordUrl(['javascript:alert(1)', 'ftp://example.com', 'file:///etc/passwd'])).toBeUndefined();
    expect(changePasswordUrl(undefined)).toBeUndefined();
  });
});

describe('insecureUrl and isLocalHost', () => {
  it('finds public http sites only', () => {
    expect(insecureUrl(['https://a.example', 'http://a.example'])).toBe('http://a.example');
    expect(insecureUrl(['HTTP://A.example'])).toBe('HTTP://A.example');
    expect(insecureUrl(['a.example', 'http://10.0.0.8', 'http://[::1]:3000', 'http://printer'])).toBeUndefined();
  });
  it('knows private ranges', () => {
    for (const host of ['localhost', 'app.localhost', 'nas.local', '127.0.0.1', '10.1.2.3', '172.16.0.1', '172.31.255.1', '192.168.0.1', '169.254.1.1', '[::1]', '[fd00::1]', 'router']) expect(isLocalHost(host), host).toBe(true);
    for (const host of ['example.com', '8.8.8.8', '172.32.0.1', '192.169.0.1', '[2606:4700::1]']) expect(isLocalHost(host), host).toBe(false);
  });
});

describe('same website', () => {
  // The same table as `crates/octapass-core/src/matching/websites.rs`: (kept, its mode, other, other's mode, same).
  const cases: [string, string | undefined, string, string | undefined, boolean][] = [
    // The default: the same host, whatever else is written.
    ['https://saasify.example.com', 'baseDomain', 'https://saasify.example.com/', undefined, true],
    ['https://saasify.example.com', 'baseDomain', 'https://saasify.example.com/login', undefined, true],
    ['https://saasify.example.com', 'baseDomain', 'http://saasify.example.com', undefined, true],
    ['https://saasify.example.com', 'baseDomain', 'HTTPS://Saasify.Example.COM/', undefined, true],
    ['https://saasify.example.com', 'baseDomain', 'https://www.saasify.example.com', undefined, true],
    ['www.saasify.example.com', 'baseDomain', 'saasify.example.com', undefined, true],
    ['https://saasify.example.com', 'baseDomain', 'saasify.example.com:8443/a?b=c#d', undefined, true],
    ['https://saasify.example.com.', 'baseDomain', 'https://saasify.example.com', undefined, true],
    ['localhost:3000', 'baseDomain', 'http://localhost:8080/', undefined, true],
    ['https://bücher.example', 'baseDomain', 'https://xn--bcher-kva.example/', undefined, true],
    ['https://a.example.com', 'baseDomain', 'https://b.example.com', undefined, false],
    ['https://a.example.com', 'baseDomain', 'https://example.com', undefined, false],
    ['https://example.com', 'baseDomain', 'https://example.org', undefined, false],
    ['https://saasify.example.com', 'subdomains', 'http://www.saasify.example.com/login', undefined, true],
    ['https://saasify.example.com', undefined, 'https://saasify.example.com/', 'subdomains', true],
    ['https://a.example.com', 'subdomains', 'https://example.com', undefined, false],
    // The kept URL's mode decides; a URL without one joins it.
    ['https://app.example.com', 'host', 'https://app.example.com/login', undefined, true],
    ['https://app.example.com', 'host', 'https://APP.example.com:443', undefined, true],
    ['https://app.example.com:8443', 'host', 'http://app.example.com:8443', undefined, true],
    ['https://app.example.com', 'host', 'http://app.example.com', undefined, false],
    ['https://app.example.com', 'host', 'https://www.app.example.com', undefined, false],
    ['https://app.example.com', 'host', 'https://app.example.com:8443', undefined, false],
    ['localhost:3000', 'host', 'localhost:8080', undefined, false],
    ['https://example.com/admin', 'startsWith', 'HTTPS://Example.com:443/admin', undefined, true],
    ['https://example.com', 'startsWith', 'https://example.com/', undefined, true],
    ['https://example.com/admin', 'startsWith', 'https://example.com/admin/', undefined, false],
    ['https://example.com/admin', 'startsWith', 'https://example.com', undefined, false],
    ['https://example.com/admin', 'startsWith', 'http://example.com/admin', undefined, false],
    ['https://example.com', 'never', 'https://example.com/', undefined, true],
    ['https://example.com', 'never', 'https://example.com/login', undefined, false],
    // Regular expressions are text, on either side.
    ['^https://example\\.com/', 'regex', ' ^https://example\\.com/ ', undefined, true],
    ['^https://example\\.com/', 'regex', 'https://example.com/', undefined, false],
    ['https://example.com', 'baseDomain', 'example.com', 'regex', false],
    // Not web addresses: the same text only.
    ['androidapp://com.example.app', 'baseDomain', 'androidapp://com.example.app', undefined, true],
    ['androidapp://com.example.app', 'baseDomain', 'androidapp://com.example.other', undefined, false],
    ['not a url', 'baseDomain', 'not a url', undefined, true],
    ['mailto:a@example.com', 'baseDomain', 'https://example.com', undefined, false],
  ];

  it.each(cases)('%s (%s) vs %s (%s): %s', (kept, keptMode, other, otherMode, same) => {
    expect(sameWebsite(kept, keptMode, other, otherMode)).toBe(same);
  });

  it('keeps the first of each website', () => {
    const urls = ['https://saasify.example.com', 'https://other.example', 'https://saasify.example.com/', 'http://saasify.example.com/login', 'https://other.example/x'];
    expect(uniqueWebsites(urls)).toEqual(['https://saasify.example.com', 'https://other.example']);
  });

  it('keeps the kept mode and drops the others', () => {
    const overview = {
      urls: ['https://app.example.com', 'https://app.example.com/login', 'https://APP.example.com', '^x$'],
      urlMatch: { 'https://app.example.com': 'host', 'https://APP.example.com': 'never', '^x$': 'regex' } as const,
    };
    expect(withUniqueWebsites({ ...overview, urlMatch: { ...overview.urlMatch } })).toEqual({
      urls: ['https://app.example.com', '^x$'],
      urlMatch: { 'https://app.example.com': 'host', '^x$': 'regex' },
    });
    expect(withUniqueWebsites({ urls: ['https://a.example', 'https://a.example/'], urlMatch: { 'https://a.example/': 'never' as const } })).toEqual({ urls: ['https://a.example'] });
  });

  it('compares a new address with the saved ones', () => {
    expect(hasWebsite(['https://app.example.com'], undefined, 'https://www.app.example.com/')).toBe(true);
    expect(hasWebsite(['https://app.example.com'], { 'https://app.example.com': 'host' }, 'https://www.app.example.com/')).toBe(false);
    expect(hasWebsite(['https://app.example.com'], { 'https://app.example.com': 'host' }, 'https://app.example.com/login')).toBe(true);
  });

  it('compares unknown modes as text', () => {
    expect(sameWebsite('https://a.example', 'exact', 'https://a.example/', undefined)).toBe(false);
  });
});
