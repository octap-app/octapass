import { VaultError } from './errors';

/** The hosted Octa Pass service. */
export const HOSTED_SERVER_URL = 'https://vault.octap.app';

/** The hosted web vault, where links made on the hosted service open. */
export const HOSTED_WEB_VAULT_URL = 'https://vault.octap.app';

/** The server's origin. HTTPS only, except plain HTTP to this computer for development. */
export function serverOrigin(serverUrl: string): string {
  let url: URL;
  try {
    url = new URL(serverUrl.trim());
  } catch {
    throw new VaultError('insecureServerUrl');
  }
  const local = url.hostname === 'localhost' || url.hostname === '127.0.0.1';
  if (url.protocol !== 'https:' && !(local && url.protocol === 'http:')) throw new VaultError('insecureServerUrl');
  return url.origin;
}

/**
 * The address of a share link made in an app, whose own pages aren't on a web vault's origin:
 * `<web vault>/s/<id>?server=<origin>#<key>`. Links made on the hosted service open in the hosted
 * web vault; any other server serves its own web vault (`OCTAPASS_WEB_DIR`), so they open there.
 * The key stays in the fragment, which browsers never send.
 */
export function appShareLinkUrl(serverUrl: string, link: { id: string; key: string }): string {
  const server = serverOrigin(serverUrl);
  const hosted = server === new URL(HOSTED_SERVER_URL).origin;
  const url = new URL(`/s/${encodeURIComponent(link.id)}`, hosted ? HOSTED_WEB_VAULT_URL : server);
  if (!hosted) url.searchParams.set('server', server);
  url.hash = link.key;
  return url.href;
}
