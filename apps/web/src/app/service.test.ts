import { HOSTED_SERVER_URL } from '@octapass/vault-client';
import { defaultServerUrl } from './service';

describe('defaultServerUrl', () => {
  it('uses the page origin for a web vault served by the server', () => {
    expect(defaultServerUrl('same-origin', 'https://pass.example.com', false)).toBe('https://pass.example.com');
  });

  it('uses the configured server, then a local one in development, then the hosted service', () => {
    expect(defaultServerUrl('https://vault.example.com', 'https://web.example.com', true)).toBe('https://vault.example.com');
    expect(defaultServerUrl(undefined, 'http://localhost:5174', true)).toBe('http://localhost:8080');
    expect(defaultServerUrl('', 'https://web.example.com', false)).toBe(HOSTED_SERVER_URL);
  });
});
