// Relays passkey requests from the MAIN-world script to the service worker, and frames the Open
// Pass prompt (an extension page the website can't script) while the user decides.

import { PASSKEY_PORT, type PasskeyPortMessage } from '../shared/passkey';
import { PROMPT_HELLO, promptHeight, type PromptHello, type PromptMessage } from '../shared/passkeyFrame';
import { isPageMessage, type PageReply } from '../page/bridge';

/** The frame's height before the prompt says how tall it is. */
const INITIAL_HEIGHT = 236;

// In the shadow root, which the page's stylesheets can't reach. The iframe resets everything a
// page could set on it; the wrapper draws the card, its entrance and its height changes.
const CSS = `
.frame { all: initial; position: fixed; inset-block-start: 12px; inset-inline-end: 12px; display: block;
  inline-size: min(380px, calc(100vw - 24px)); block-size: ${INITIAL_HEIGHT}px; max-block-size: calc(100vh - 24px);
  border-radius: 16px; overflow: hidden; box-shadow: 0 1px 2px rgb(11 18 32 / 0.08), 0 16px 40px -12px rgb(11 18 32 / 0.35); }
iframe { all: initial; display: block; inline-size: 100%; block-size: 100%; border: 0; color-scheme: normal; }
@media (prefers-reduced-motion: no-preference) {
  .frame { animation: enter 200ms cubic-bezier(0.2, 0.7, 0.2, 1); transition: block-size 160ms cubic-bezier(0.2, 0.7, 0.2, 1); }
  @keyframes enter { from { opacity: 0; transform: translateY(-8px) scale(0.98); } }
}`;

function styleRoot(root: ShadowRoot): void {
  if ('adoptedStyleSheets' in root) {
    try {
      const sheet = new CSSStyleSheet();
      sheet.replaceSync(CSS);
      root.adoptedStyleSheets = [sheet];
      // Firefox can refuse a sheet made in a content script's isolated world; a <style> works there.
      if (root.adoptedStyleSheets.includes(sheet)) return;
    } catch {
      // Below.
    }
  }
  const style = document.createElement('style');
  style.textContent = CSS;
  root.append(style);
}

/**
 * The prompt sits in a closed shadow root in the top layer, out of the page's reach. It tells us its
 * height over a MessageChannel we hand it, addressed to the extension's origin only and naming the
 * request (which the page never learns), so the page can neither read the size nor fake it.
 */
export function showPrompt(requestId: string, onClose: () => void): () => void {
  const host = document.createElement('octapass-passkey');
  host.setAttribute('popover', 'manual');
  host.style.cssText = 'all: initial !important; position: fixed !important; inset: 0 !important; inline-size: 0 !important; block-size: 0 !important; overflow: visible !important; border: 0 !important; background: none !important';
  const root = host.attachShadow({ mode: 'closed' });
  styleRoot(root);
  const wrapper = document.createElement('div');
  wrapper.className = 'frame';
  const frame = document.createElement('iframe');
  const src = chrome.runtime.getURL(`passkey.html#${requestId}`);
  frame.src = src;
  frame.title = 'Octa Pass';
  frame.allow = 'publickey-credentials-get; publickey-credentials-create';
  wrapper.append(frame);
  root.append(wrapper);

  const channel = new MessageChannel();
  channel.port1.onmessage = ({ data }: MessageEvent<PromptMessage>) => {
    if (data?.type === 'height') {
      const height = promptHeight(data.height);
      if (height !== null) wrapper.style.setProperty('block-size', `${height}px`);
    } else if (data?.type === 'close') {
      onClose();
    }
  };
  // Only the first load is ours: if the page navigates the frame elsewhere, it gets no port.
  frame.addEventListener(
    'load',
    () => frame.contentWindow?.postMessage({ type: PROMPT_HELLO, requestId } satisfies PromptHello, new URL(src).origin, [channel.port2]),
    { once: true },
  );

  // Everything outside an open modal <dialog> is inert, so the prompt couldn't be answered there.
  (document.querySelector('dialog:modal') ?? document.body ?? document.documentElement).append(host);
  host.showPopover?.();
  return () => {
    channel.port1.close();
    host.remove();
  };
}

export function startPasskeyRelay(): void {
  window.addEventListener('message', (event) => {
    if (event.source !== window || !isPageMessage(event.data) || !event.ports[0]) return;
    const reply = event.ports[0];
    const port = chrome.runtime.connect({ name: PASSKEY_PORT });
    let hide: (() => void) | undefined;
    let done = false;
    const finish = (result: PageReply) => {
      done = true;
      hide?.();
      reply.postMessage(result);
      reply.close();
      port.disconnect();
    };
    port.onMessage.addListener((message: PasskeyPortMessage) => {
      // The prompt's close button, when the service worker no longer knows the request: the page
      // hears "not allowed", as if the user cancelled, and the worker drops it with the port.
      if (message.type === 'pending') {
        hide = showPrompt(message.requestId, () => {
          if (!done) finish({ kind: 'error', name: 'NotAllowedError', message: 'The user cancelled.' });
        });
      } else finish(message.result);
    });
    // The service worker restarted mid-request: the page mustn't wait forever.
    port.onDisconnect.addListener(() => {
      if (!done) finish({ kind: 'error', name: 'NotAllowedError', message: 'The request was interrupted.' });
    });
    // The page gave up (AbortSignal): close the prompt.
    reply.onmessage = () => {
      done = true;
      hide?.();
      port.disconnect();
    };
    port.postMessage(event.data.request);
  });
}
