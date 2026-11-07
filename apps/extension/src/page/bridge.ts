// The message format between the MAIN-world script and the content script. The page can read and
// forge these, which gains it nothing: the service worker takes the origin from the browser, and
// only the Octa Pass prompt (an extension page) can approve a request.

import type { PasskeyCall, PasskeyResult } from '../shared/passkey';

export const PAGE_SOURCE = 'octapass-passkey';

export type PageRequest = PasskeyCall;
export type PageReply = PasskeyResult;

export function isPageMessage(data: unknown): data is { source: typeof PAGE_SOURCE; request: PageRequest } {
  return typeof data === 'object' && data !== null && (data as { source?: unknown }).source === PAGE_SOURCE && 'request' in data;
}
