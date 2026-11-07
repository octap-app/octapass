import { MAX_PROMPT_HEIGHT, PROMPT_HELLO } from '../shared/passkeyFrame';
import { showPrompt } from './passkeyRelay';

let roots: ShadowRoot[] = [];
const attach = HTMLElement.prototype.attachShadow;
beforeEach(() => {
  roots = [];
  vi.spyOn(HTMLElement.prototype, 'attachShadow').mockImplementation(function (this: HTMLElement, init: ShadowRootInit) {
    const root = attach.call(this, init);
    roots.push(root);
    return root;
  });
});
afterEach(() => {
  vi.restoreAllMocks();
  document.body.replaceChildren();
});

const settle = () => new Promise((resolve) => setTimeout(resolve, 10));

describe('the passkey prompt’s frame', () => {
  it('hands the prompt a port, for the extension’s origin only, and sizes itself as told', async () => {
    const onClose = vi.fn();
    const hide = showPrompt('request-1', onClose);
    const host = document.querySelector('octapass-passkey')!;
    expect(host.shadowRoot).toBeNull();
    const frame = roots[0]!.querySelector('iframe')!;
    const wrapper = frame.parentElement!;
    expect(frame.src).toBe(chrome.runtime.getURL('passkey.html#request-1'));

    const post = vi.spyOn(frame.contentWindow!, 'postMessage').mockImplementation(() => undefined);
    frame.dispatchEvent(new Event('load'));
    // A second load is the page navigating the frame: it gets nothing.
    frame.dispatchEvent(new Event('load'));
    expect(post).toHaveBeenCalledOnce();
    const [message, origin, transfer] = post.mock.calls[0] as unknown as [unknown, string, MessagePort[]];
    expect(message).toEqual({ type: PROMPT_HELLO, requestId: 'request-1' });
    expect(origin).toBe(new URL(chrome.runtime.getURL('')).origin);

    const port = transfer[0]!;
    port.postMessage({ type: 'height', height: 333.2 });
    await settle();
    expect(wrapper.style.getPropertyValue('block-size')).toBe('333px');
    port.postMessage({ type: 'height', height: 9000 });
    await settle();
    expect(wrapper.style.getPropertyValue('block-size')).toBe(`${MAX_PROMPT_HEIGHT}px`);
    port.postMessage({ type: 'height', height: 'tall' });
    port.postMessage({ type: 'nonsense' });
    await settle();
    expect(wrapper.style.getPropertyValue('block-size')).toBe(`${MAX_PROMPT_HEIGHT}px`);
    expect(onClose).not.toHaveBeenCalled();

    port.postMessage({ type: 'close' });
    await settle();
    expect(onClose).toHaveBeenCalledOnce();
    hide();
    expect(document.querySelector('octapass-passkey')).toBeNull();
    port.close();
  });

  it('opens inside an open modal dialog', () => {
    const dialog = document.createElement('dialog');
    document.body.append(dialog);
    const modal = vi.spyOn(document, 'querySelector').mockImplementation((selector: string) => (selector === 'dialog:modal' ? dialog : null));
    const hide = showPrompt('request-2', () => undefined);
    modal.mockRestore();
    expect(dialog.querySelector('octapass-passkey')).not.toBeNull();
    hide();
  });
});
