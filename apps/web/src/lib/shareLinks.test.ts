import { parseShareLink, shareLinkUrl } from './shareLinks';

describe('share link addresses', () => {
  const link = { id: 'AbC_d-e', key: 'k3y-in_the-fragment' };

  it('keeps the key in the fragment and leaves the default server out', () => {
    const url = shareLinkUrl('https://vault.octap.app', link, 'https://vault.octap.app', 'https://vault.octap.app/');
    expect(url).toBe('https://vault.octap.app/s/AbC_d-e#k3y-in_the-fragment');
    const parsed = new URL(url);
    expect(parseShareLink('AbC_d-e', parsed.search, parsed.hash, 'https://vault.octap.app')).toEqual({ id: 'AbC_d-e', key: 'k3y-in_the-fragment', serverUrl: 'https://vault.octap.app' });
  });

  it('names a self-hosted server in the query', () => {
    const url = new URL(shareLinkUrl('https://vault.octap.app', link, 'https://vault.example.org/', 'https://vault.octap.app'));
    expect(url.searchParams.get('server')).toBe('https://vault.example.org');
    expect(parseShareLink(link.id, url.search, url.hash, 'https://vault.octap.app').serverUrl).toBe('https://vault.example.org');
  });

  it('refuses a link that names a server without HTTPS', () => {
    for (const server of ['http://evil.example', 'javascript:alert(1)', 'not a url', 'ftp://files.example']) {
      expect(parseShareLink('x', `?server=${encodeURIComponent(server)}`, '#k', 'https://vault.octap.app').serverUrl).toBe('');
    }
    expect(parseShareLink('x', '?server=http://localhost:8080', '#k', 'https://vault.octap.app').serverUrl).toBe('http://localhost:8080');
  });

  it('reports a missing key as empty', () => {
    expect(parseShareLink('x', '', '', 'https://vault.octap.app').key).toBe('');
  });
});
