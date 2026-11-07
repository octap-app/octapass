import { bytesToHex } from './encoding';

export const PWNED_PASSWORDS_URL = 'https://api.pwnedpasswords.com';

async function sha1Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(text));
  return bytesToHex(new Uint8Array(digest)).toUpperCase();
}

function parseRange(body: string): Map<string, number> {
  const counts = new Map<string, number>();
  for (const line of body.split(/\r?\n/)) {
    const [suffix, count] = line.trim().split(':');
    const n = Number(count);
    // Padding entries (Add-Padding) carry a count of 0 and are not real hashes.
    if (suffix && n > 0) counts.set(suffix.toUpperCase(), n);
  }
  return counts;
}

/**
 * Checks passwords against Pwned Passwords with k-anonymity: only the first 5 hex characters of the
 * SHA-1 leave the device, and the response is padded so its size doesn't hint at the prefix either.
 * Resolves to how many breaches the password appears in (0 = not found); rejects when the API fails.
 */
export function createBreachChecker(
  opts: { fetch?: typeof fetch; baseUrl?: string } = {},
): (password: string) => Promise<number> {
  // Wrapped so a bare `fetch` isn't called with the wrong `this`, which browsers reject.
  const fetchRange = opts.fetch ?? ((input: RequestInfo | URL, init?: RequestInit) => fetch(input, init));
  const baseUrl = (opts.baseUrl ?? PWNED_PASSWORDS_URL).replace(/\/+$/, '');
  const cache = new Map<string, Promise<Map<string, number>>>();

  const range = (prefix: string) => {
    let pending = cache.get(prefix);
    if (!pending) {
      pending = (async () => {
        const response = await fetchRange(`${baseUrl}/range/${prefix}`, {
          headers: { 'Add-Padding': 'true' },
          referrerPolicy: 'no-referrer',
        });
        if (!response.ok) throw new Error(`Pwned Passwords answered ${response.status}`);
        return parseRange(await response.text());
      })();
      // Forget failures so the next check retries instead of replaying the error.
      pending.catch(() => cache.delete(prefix));
      cache.set(prefix, pending);
    }
    return pending;
  };

  return async (password) => {
    const hash = await sha1Hex(password);
    const counts = await range(hash.slice(0, 5));
    return counts.get(hash.slice(5)) ?? 0;
  };
}
