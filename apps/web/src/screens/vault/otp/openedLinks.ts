/**
 * One-time code setup links the system opened Octa Pass with (Set Up Codes In on the phone and the
 * Mac, a website, the Camera's QR code button): what to show before anything is saved. The vault's
 * `otpauth` importer then adds them, joining the login with the same name. Used by the phone app
 * and the desktop app.
 */
export type OpenedLink =
  | { kind: 'code'; link: string; issuer?: string; account?: string }
  /** A Google Authenticator export: one or more codes. */
  | { kind: 'export'; link: string };

export function readLink(link: string): OpenedLink | undefined {
  let url: URL;
  try {
    url = new URL(link);
  } catch {
    return undefined;
  }
  const scheme = url.protocol.toLowerCase();
  if (scheme === 'otpauth-migration:') return url.searchParams.get('data') ? { kind: 'export', link } : undefined;
  if (scheme !== 'otpauth:' || !['totp', 'hotp'].includes(url.hostname.toLowerCase()) || !url.searchParams.get('secret')) return undefined;
  let label = url.pathname.replace(/^\/+/, '');
  try {
    label = decodeURIComponent(label);
  } catch {
    // Kept as it is.
  }
  const colon = label.indexOf(':');
  const labelIssuer = colon >= 0 ? label.slice(0, colon).trim() : undefined;
  const account = (colon >= 0 ? label.slice(colon + 1) : label).trim() || undefined;
  const issuer = url.searchParams.get('issuer')?.trim() || labelIssuer || undefined;
  return { kind: 'code', link, issuer, account };
}
