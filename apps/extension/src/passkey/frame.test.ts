import { MAX_PROMPT_HEIGHT, MIN_PROMPT_HEIGHT, PROMPT_HELLO, promptHeight } from '../shared/passkeyFrame';
import { linkFrame } from './frame';

/** A frame's window whose parent is `parent`, for posting hellos into. */
function frameWindow(parent: object) {
  const target = new EventTarget() as EventTarget & { parent: object };
  target.parent = parent;
  return target as unknown as Window;
}

function hello(target: Window, data: unknown, source: unknown, port?: MessagePort) {
  target.dispatchEvent(new MessageEvent('message', { data, source: source as MessageEventSource, ports: port ? [port] : [] }));
}

function received(port: MessagePort): unknown[] {
  const messages: unknown[] = [];
  port.onmessage = (event) => messages.push(event.data);
  return messages;
}

const settle = () => new Promise((resolve) => setTimeout(resolve, 10));

describe('the prompt’s frame size', () => {
  it('is clamped, and nonsense is ignored', () => {
    expect(promptHeight(310.4)).toBe(310);
    expect(promptHeight(20)).toBe(MIN_PROMPT_HEIGHT);
    expect(promptHeight(5000)).toBe(MAX_PROMPT_HEIGHT);
    for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, '300', null, undefined, {}]) expect(promptHeight(bad)).toBeNull();
  });

  it('goes to the content script once its hello names this request, from the parent', async () => {
    const parent = {};
    const target = frameWindow(parent);
    const link = linkFrame('request-1', target);
    link.height(300);

    // The page shares the parent's window, but doesn't know the request.
    const page = new MessageChannel();
    const pageGot = received(page.port1);
    hello(target, { type: PROMPT_HELLO, requestId: 'guess' }, parent, page.port2);
    // From somewhere else entirely.
    const other = new MessageChannel();
    const otherGot = received(other.port1);
    hello(target, { type: PROMPT_HELLO, requestId: 'request-1' }, {}, other.port2);

    const ours = new MessageChannel();
    const got = received(ours.port1);
    hello(target, { type: PROMPT_HELLO, requestId: 'request-1' }, parent, ours.port2);
    link.height(300);
    link.height(420);
    link.close();
    await settle();
    expect(got).toEqual([{ type: 'height', height: 300 }, { type: 'height', height: 420 }, { type: 'close' }]);
    expect(pageGot).toEqual([]);
    expect(otherGot).toEqual([]);

    // Later hellos can't take the port over.
    const late = new MessageChannel();
    const lateGot = received(late.port1);
    hello(target, { type: PROMPT_HELLO, requestId: 'request-1' }, parent, late.port2);
    link.height(380);
    await settle();
    expect(lateGot).toEqual([]);
    for (const channel of [page, other, ours, late]) channel.port1.close();
  });
});
