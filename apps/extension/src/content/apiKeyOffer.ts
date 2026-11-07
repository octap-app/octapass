// Offering to save a pasted API key. The key stays in this closure, in the content script's isolated
// world, where the page can't reach it: only what kind it is goes to the service worker to ask whether
// to offer, and the value follows only if the user chooses Save. Answering, or waiting too long, forgets it.

import type { ApiKeyPaste } from '@octapass/autofill';
import type { SaveAnswer, SavePrompt, SaveResponse } from '../shared/messages';

/** As long as the service worker keeps the prompt. */
export const OFFER_MS = 2 * 60_000;

export interface ApiKeyOfferDeps {
  offer(kind: ApiKeyPaste['kind']): Promise<SaveResponse | undefined>;
  /** Shows the prompt; returns a function that takes it away. */
  show(prompt: SavePrompt, answered: (answer: SaveAnswer) => void): () => void;
  answer(id: string, answer: SaveAnswer, credential?: string): Promise<boolean | null | undefined>;
  saved(ok: boolean): void;
}

export function apiKeyOffers({ offer, show, answer, saved }: ApiKeyOfferDeps): (paste: ApiKeyPaste) => Promise<void> {
  let close: (() => void) | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let latest = 0;
  /** The user said no on this page: another paste shouldn't ask again. */
  let quiet = false;

  const dismiss = () => {
    clearTimeout(timer);
    close?.();
    close = undefined;
  };

  return async (paste) => {
    if (quiet) return;
    const mine = ++latest;
    const response = await offer(paste.kind).catch(() => null);
    // A newer paste replaces this one, whether or not the worker offers it.
    if (mine !== latest || !response || !('prompt' in response)) return;
    const { prompt } = response;
    dismiss();
    close = show(prompt, (choice) => {
      dismiss();
      if (choice === 'save') {
        void answer(prompt.id, choice, paste.value).then(
          (ok) => saved(ok === true),
          () => saved(false),
        );
      } else {
        quiet = true;
        void answer(prompt.id, choice).catch(() => undefined);
      }
    });
    timer = setTimeout(dismiss, OFFER_MS);
  };
}
