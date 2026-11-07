import '@testing-library/jest-dom/vitest';

// jsdom has <dialog> but not its modal methods (the web vault's dialogs use them).
HTMLDialogElement.prototype.showModal ??= function (this: HTMLDialogElement) {
  this.setAttribute('open', '');
};
HTMLDialogElement.prototype.close ??= function (this: HTMLDialogElement) {
  this.removeAttribute('open');
};
