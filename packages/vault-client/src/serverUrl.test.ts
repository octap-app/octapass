import { describe, expect, it } from 'vitest';
import { VaultError } from './errors';
import { appShareLinkUrl, HOSTED_SERVER_URL } from './serverUrl';

describe('appShareLinkUrl', () => {
  const link = { id: 'abc/1', key: 'k3y' };

  it('opens links made on the hosted service in the hosted web vault', () => {
    expect(appShareLinkUrl(`${HOSTED_SERVER_URL}/`, link)).toBe('https://vault.octap.app/s/abc%2F1#k3y');
  });

  it('opens links made on another server in that server’s own web vault, naming the server', () => {
    const url = new URL(appShareLinkUrl('https://pass.example.org/some/path', link));
    expect(url.origin).toBe('https://pass.example.org');
    expect(url.pathname).toBe('/s/abc%2F1');
    expect(url.searchParams.get('server')).toBe('https://pass.example.org');
    expect(url.hash).toBe('#k3y');
  });

  it('refuses a server that isn’t HTTPS', () => {
    expect(() => appShareLinkUrl('http://pass.example.org', link)).toThrow(VaultError);
  });
});
