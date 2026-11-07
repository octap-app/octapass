// Share link addresses: `https://<web vault>/s/<id>#<key>`. The key lives in the fragment, which
// browsers never send to a server. A link made on another server than the default names it in
// `?server=`, so the viewer knows where to fetch the ciphertext from.

export interface ShareLinkAddress {
  id: string;
  /** Empty when the fragment is missing, for example when the link was cut short. */
  key: string;
  /** Empty when the link names a server that isn't HTTPS: such a link isn't opened at all. */
  serverUrl: string;
}

/** Only HTTPS servers (or a local development server) may serve a share link's ciphertext. */
function secureServer(value: string): string {
  try {
    const url = new URL(value);
    const local = url.hostname === 'localhost' || url.hostname === '127.0.0.1' || url.hostname === '[::1]';
    return url.protocol === 'https:' || (url.protocol === 'http:' && local) ? url.origin : '';
  } catch {
    return '';
  }
}

export function shareLinkUrl(webOrigin: string, link: { id: string; key: string }, serverUrl: string, defaultServerUrl: string): string {
  const url = new URL(`/s/${encodeURIComponent(link.id)}`, webOrigin);
  if (new URL(serverUrl).origin !== new URL(defaultServerUrl).origin) url.searchParams.set('server', new URL(serverUrl).origin);
  url.hash = link.key;
  return url.href;
}

export function parseShareLink(id: string, search: string, hash: string, defaultServerUrl: string): ShareLinkAddress {
  const named = new URLSearchParams(search).get('server');
  return { id, key: hash.replace(/^#/, ''), serverUrl: named ? secureServer(named) : defaultServerUrl };
}
