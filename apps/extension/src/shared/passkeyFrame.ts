// Between the passkey prompt (passkey.html, framed in the page) and the content script that frames it.
// The content script posts a hello to the frame, addressed to the extension's origin and carrying a
// MessagePort; the prompt keeps that port only when the hello names its own request, which the page
// never sees. Everything after goes over the port, out of the page's reach.

export const PROMPT_HELLO = 'octapass:passkey-frame';

export interface PromptHello {
  type: typeof PROMPT_HELLO;
  requestId: string;
}

/**
 * Prompt to content script. `height`: how tall its content is, in CSS px. `close`: the user closed a
 * prompt the service worker no longer knows (a request that ended), so only the content script can
 * take it away, cancelling the request.
 */
export type PromptMessage = { type: 'height'; height: number } | { type: 'close' };

export const MIN_PROMPT_HEIGHT = 200;
export const MAX_PROMPT_HEIGHT = 520;

/** The frame height for what the prompt asked for, or null for nonsense. */
export function promptHeight(height: unknown): number | null {
  if (typeof height !== 'number' || !Number.isFinite(height)) return null;
  return Math.round(Math.min(MAX_PROMPT_HEIGHT, Math.max(MIN_PROMPT_HEIGHT, height)));
}

export function isPromptHello(data: unknown, requestId: string): data is PromptHello {
  return typeof data === 'object' && data !== null && (data as PromptHello).type === PROMPT_HELLO && (data as PromptHello).requestId === requestId;
}
