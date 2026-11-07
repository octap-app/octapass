import type { SuggestionKind } from '../types';

const svg = (body: string) =>
  `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${body}</svg>`;

export const GLYPHS: Record<SuggestionKind, string> = {
  login: svg('<circle cx="8" cy="15" r="4"/><path d="M10.8 12.2 20 3m-4 4 3 3m-6-1 2 2"/>'),
  'generated-password': svg('<path d="M12 3v3m0 12v3M3 12h3m12 0h3M5.6 5.6l2.1 2.1m8.6 8.6 2.1 2.1M5.6 18.4l2.1-2.1m8.6-8.6 2.1-2.1"/>'),
  'masked-email': svg('<rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3 7 9 6 9-6"/>'),
  'one-time-code': svg('<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>'),
  card: svg('<rect x="2" y="5" width="20" height="14" rx="2"/><path d="M2 10h20M6 15h4"/>'),
  identity: svg('<circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/>'),
  'api-credential': svg('<path d="m8 8-5 4 5 4m8-8 5 4-5 4M14 5l-4 14"/>'),
  'frame-approval': svg('<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 9h18"/><path d="m9 15 2 2 4-4"/>'),
  'other-logins': svg('<circle cx="5" cy="12" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/>'),
  'other-login': svg('<circle cx="8" cy="15" r="4"/><path d="M10.8 12.2 20 3m-4 4 3 3m-6-1 2 2"/>'),
};

/** The unlock entry, while the vault is locked. */
export const LOCK = svg('<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>');

/** At the end of the entry that opens into more entries (drawn for left-to-right; mirrored in CSS). */
export const CHEVRON = svg('<path d="m9 6 6 6-6 6"/>');

/** The app tile (white monogram on the gradient), for the in-field icon and the menu header: below 24 px the bare mark is too thin. */
export const TILE = `<svg viewBox="0 0 64 64" aria-hidden="true"><defs><linearGradient id="op-t" x1="0" y1="0" x2="64" y2="64" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#2456F0"/><stop offset="1" stop-color="#10B77F"/></linearGradient></defs><rect width="64" height="64" rx="16" fill="url(#op-t)"/><g transform="translate(32 32.6) scale(0.66) translate(-32 -33.5)"><g fill="none" stroke="#FFFFFF" stroke-width="5.2" stroke-linecap="round" stroke-linejoin="round"><path d="M19.25 51.58A25.5 25.5 0 1 1 37.74 54.35"/><path d="M19.20 36.31A14.5 14.5 0 1 1 28.40 43.55L28.4 61.5"/></g><path d="M32 23.4a3.9 3.9 0 0 1 2.2 7.1l1.1 5.4h-6.6l1.1-5.4A3.9 3.9 0 0 1 32 23.4Z" fill="#FFFFFF"/></g></svg>`;
