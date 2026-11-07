import { tokenCss } from './tokens';

/**
 * Sizes in px, not the tokens' rem: a rem follows the page's root font size, and pages that set
 * `html { font-size: 62.5% }` (common) shrank the menu to about 7.5px text. Browser zoom still scales px.
 */
const SIZES = `.root { --text-xs: 12px; --text-sm: 14px; --text-detail: 13px; --radius-sm: 8px; --radius: 12px; }`;

const RESET = `${SIZES}
.root { all: initial; display: block; font-family: var(--font-sans); color: var(--ink); font-size: 14px;
  -webkit-font-smoothing: antialiased; line-height: 1.35; -webkit-text-size-adjust: 100%; text-size-adjust: 100%; }
.root *, .root *::before, .root *::after { box-sizing: border-box; }`;

/** The list's tallest; `Menu` places the panel without measuring it when this (plus the header and footer) fits. */
export const LIST_MAX_HEIGHT = 288;

export const MENU_CSS = `${tokenCss('.root')}
${RESET}
.panel { background: var(--raised); border: 1px solid var(--line); border-radius: var(--radius);
  box-shadow: var(--shadow-pop); overflow: hidden; }

.head { display: flex; align-items: center; gap: 8px; padding: 10px 12px 6px; font-size: var(--text-xs);
  color: var(--mist); white-space: nowrap; }
.head svg { width: 18px; height: 18px; flex: none; }
.brand { font-weight: 650; color: var(--ink); letter-spacing: -0.01em; flex: none; }
.dot { flex: none; }
.site { min-width: 0; overflow: hidden; text-overflow: ellipsis; direction: ltr; unicode-bidi: isolate; }

.list { padding: 2px 6px 6px; max-height: ${LIST_MAX_HEIGHT}px; overflow-y: auto; overscroll-behavior: contain;
  outline: none; scrollbar-width: thin; }
.sep { height: 1px; background: var(--line); margin: 4px 8px; }
.empty { padding: 10px 8px 6px; color: var(--mist); font-size: var(--text-sm); }
.foot[hidden] { display: none; }

.item { display: flex; align-items: center; gap: 10px; min-height: 44px; padding: 6px 8px; border-radius: var(--radius-sm);
  cursor: pointer; outline: none; color: var(--ink); font-size: var(--text-sm); }
.item:hover { background: var(--hover); }
.item:focus { background: var(--selected); box-shadow: inset 0 0 0 1.5px var(--focus); }
.item[aria-disabled='true'] { cursor: default; color: var(--mist); }
.item[aria-disabled='true']:hover { background: transparent; }
.item[aria-disabled='true'] .glyph { opacity: 0.6; }

.glyph { flex: none; width: 32px; height: 32px; border-radius: var(--radius-sm); display: grid; place-items: center;
  background: var(--tile); color: var(--trust-text); }
.glyph svg { width: 18px; height: 18px; }
.glyph.letter { background: color-mix(in srgb, var(--trust) 12%, var(--tile)); font-weight: 650; font-size: 15px; line-height: 1; }
.glyph.letter.alt { background: color-mix(in srgb, var(--free) 14%, var(--tile)); color: var(--free-text); }
.glyph.letter::before { content: attr(data-letter); }
.glyph.lock { background: var(--selected); }
.glyph.site { background: #fff; box-shadow: inset 0 0 0 1px rgb(11 18 32 / 0.08); }
.glyph canvas { width: 20px; height: 20px; }

.text { flex: 1; display: flex; flex-direction: column; gap: 1px; min-width: 0; }
/* Each value in its own direction (an email in an Arabic menu), lined up with the menu's side. */
.title, .detail { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; unicode-bidi: plaintext; text-align: left; }
[dir='rtl'] .title, [dir='rtl'] .detail { text-align: right; }
.title { font-weight: 600; }
.detail { color: var(--mist); font-size: var(--text-detail); }
.detail.wrap { white-space: normal; overflow-wrap: anywhere; }
.detail.mono { font-family: var(--font-mono); font-size: var(--text-detail); color: var(--ink); direction: ltr;
  align-self: flex-start; max-width: 100%; margin-top: 3px; padding: 2px 6px; border-radius: 6px; background: var(--tile);
  letter-spacing: 0.02em; }
.mono .n { color: var(--trust-text); }
.mono .s { color: var(--free-text); }

.badge { flex: none; font-size: var(--text-xs); color: var(--mist); border: 1px solid var(--line); border-radius: 999px;
  padding: 1px 8px; }
/* The key that picks the focused entry. Drawn, not text, so it isn't read out with the entry. */
.item:focus::after { content: '\\21B5'; content: '\\21B5' / ''; flex: none; display: grid; place-items: center; width: 20px; height: 18px;
  border: 1px solid var(--line-strong); border-bottom-width: 2px; border-radius: 5px; color: var(--mist);
  font: 600 11px/1 var(--font-sans); }

.item.quiet { min-height: 36px; color: var(--mist); font-size: var(--text-xs); }
.item.quiet .title { font-weight: 500; }
.item.quiet .glyph { background: none; color: var(--mist); }
.chev { flex: none; width: 14px; height: 14px; color: var(--mist); }
[dir='rtl'] .chev { transform: scaleX(-1); }

kbd { display: inline-grid; place-items: center; min-width: 18px; height: 18px; padding: 0 4px; border: 1px solid var(--line-strong);
  border-bottom-width: 2px; border-radius: 5px; background: var(--surface); color: var(--mist);
  font: 600 11px/1 var(--font-sans); }
.foot { display: flex; align-items: center; justify-content: flex-end; gap: 12px; padding: 6px 12px 7px;
  border-top: 1px solid var(--line); font-size: var(--text-xs); color: var(--mist); white-space: nowrap; }
.hint { display: inline-flex; align-items: center; gap: 4px; }

@media (prefers-reduced-motion: no-preference) {
  .panel { animation: op-in var(--fast) var(--ease-out); }
  [data-place='above'] .panel { animation-name: op-up; }
  @keyframes op-in { from { opacity: 0; transform: translateY(-4px); } }
  @keyframes op-up { from { opacity: 0; transform: translateY(4px); } }
}
@media (forced-colors: active) {
  .item:focus { outline: 2px solid Highlight; outline-offset: -2px; }
}`;

export const ICON_CSS = `${tokenCss('.root')}
${RESET}
button { all: initial; display: block; width: 20px; height: 20px; cursor: pointer; border-radius: 6px; }
button:focus-visible { outline: 2px solid var(--focus); outline-offset: 1px; }
svg { display: block; width: 20px; height: 20px; }`;
