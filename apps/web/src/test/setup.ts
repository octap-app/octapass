import '@testing-library/jest-dom/vitest';
import 'fake-indexeddb/auto';
import { cleanup } from '@testing-library/react';
import { setLocale } from '../i18n';

afterEach(cleanup);

// jsdom has <dialog> but not its modal methods.
HTMLDialogElement.prototype.showModal ??= function (this: HTMLDialogElement) {
  this.setAttribute('open', '');
};
HTMLDialogElement.prototype.close ??= function (this: HTMLDialogElement) {
  this.removeAttribute('open');
};

// jsdom has no matchMedia; report a wide desktop screen.
window.matchMedia ??= (query: string) =>
  ({ matches: false, media: query, addEventListener: () => {}, removeEventListener: () => {} }) as unknown as MediaQueryList;

// Settings (theme, language) live in localStorage; each test starts from the defaults, in English.
afterEach(() => {
  localStorage.clear();
  setLocale('en');
});

// Website icons would go to the network: answer "no icon". Tests about icons stub fetch themselves.
const networkFetch = globalThis.fetch;
globalThis.fetch = (input, init) =>
  String(input instanceof Request ? input.url : input).includes('/v1/icons/') ? Promise.resolve(new Response(null, { status: 404 })) : networkFetch(input, init);
