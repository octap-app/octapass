// The prompt's side of shared/passkeyFrame.ts: waits for the content script's port, then reports
// the prompt's height on it, and can ask the content script to close a prompt that has ended.

import { isPromptHello, type PromptMessage } from '../shared/passkeyFrame';

export interface FrameLink {
  /** How tall the content is; sent once the port is here, and again whenever it changes. */
  height(px: number): void;
  /** Takes the prompt away through the content script (cancelling the request). */
  close(): void;
}

/** Listens at once, so a hello that arrives before React renders isn't missed. */
export function linkFrame(requestId: string, target: Window = window): FrameLink {
  let port: MessagePort | undefined;
  let last: number | undefined;
  let closing = false;
  const send = (message: PromptMessage) => port?.postMessage(message);

  const onMessage = (event: MessageEvent) => {
    // Posted by the content script into this frame. The page shares its window, so it could post a
    // hello too: only one naming this request, which the page never learns, is believed.
    if (port || event.source !== target.parent || !event.ports[0] || !isPromptHello(event.data, requestId)) return;
    port = event.ports[0];
    target.removeEventListener('message', onMessage);
    if (last !== undefined) send({ type: 'height', height: last });
    if (closing) send({ type: 'close' });
  };
  target.addEventListener('message', onMessage);

  return {
    height: (px) => {
      if (px === last) return;
      last = px;
      send({ type: 'height', height: px });
    },
    close: () => {
      closing = true;
      send({ type: 'close' });
    },
  };
}
