// Code that only acts on the user's own input (`event.isTrusted`) can't be driven by ordinary test
// events, which are always untrusted. This marks one as trusted, through jsdom's own implementation.

import { createRequire } from 'node:module';

interface Impl {
  isTrusted: boolean;
  _dispatch(event: Impl): boolean;
}

const { implForWrapper } = createRequire(import.meta.url)('jsdom/lib/generated/idl/utils.js') as { implForWrapper: (wrapper: object) => Impl };

/** Dispatches `event` at `target` as if the user caused it. */
export function dispatchTrusted<E extends Event>(target: EventTarget, event: E): E {
  // `dispatchEvent` marks every event untrusted, as the spec says, so this dispatches the way the
  // browser does for real input.
  const impl = implForWrapper(event);
  impl.isTrusted = true;
  implForWrapper(target)._dispatch(impl);
  return event;
}

export const trustedClick = (target: EventTarget) => dispatchTrusted(target, new MouseEvent('click', { bubbles: true, composed: true }));
