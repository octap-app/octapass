// The Octa Pass tokens the inline UI needs, copied from packages/ui/src/styles/tokens.css because a closed
// shadow root can't see the page's (or the extension's) stylesheets. tokens.test.ts keeps them in sync.

export const LIGHT = {
  '--trust': '#2456f0',
  '--trust-text': '#1d47d6',
  '--free': '#10b77f',
  '--free-text': '#077a54',
  '--surface': '#ffffff',
  '--raised': '#ffffff',
  '--tile': '#f2f3f7',
  '--ink': '#0b1220',
  '--mist': '#5e6576',
  '--line': '#e3e5ec',
  '--line-strong': '#cfd3de',
  '--focus': '#2456f0',
  '--hover': 'rgb(11 18 32 / 0.045)',
  '--selected': 'color-mix(in srgb, var(--trust) 11%, transparent)',
  '--shadow-pop': '0 1px 2px rgb(11 18 32 / 0.08), 0 16px 40px -12px rgb(11 18 32 / 0.28)',
  '--radius-sm': '0.5rem',
  '--radius': '0.75rem',
  '--text-xs': '0.75rem',
  '--text-sm': '0.875rem',
  '--font-sans': "'Mona Sans Variable', 'Mona Sans', 'Noto Sans Arabic Variable', ui-sans-serif, system-ui, -apple-system, sans-serif",
  '--font-mono': "'Monaspace Neon', ui-monospace, 'SF Mono', Menlo, monospace",
  '--fast': '140ms',
  '--ease-out': 'cubic-bezier(0.2, 0.7, 0.2, 1)',
} as const;

export const DARK: Partial<Record<keyof typeof LIGHT, string>> = {
  '--trust': '#5c86ff',
  '--trust-text': '#86a6ff',
  '--free': '#2fd394',
  '--free-text': '#4fe0a8',
  '--surface': '#0d1017',
  '--raised': '#171b26',
  '--tile': '#12151e',
  '--ink': '#f5f6f8',
  '--mist': '#9ba3b4',
  '--line': '#232838',
  '--line-strong': '#323950',
  '--focus': '#86a6ff',
  '--hover': 'rgb(255 255 255 / 0.05)',
  '--selected': 'color-mix(in srgb, var(--trust) 20%, transparent)',
  '--shadow-pop': '0 0 0 1px rgb(255 255 255 / 0.08), 0 20px 50px -12px rgb(0 0 0 / 0.8)',
};

const declarations = (tokens: Partial<Record<string, string>>) =>
  Object.entries(tokens)
    .map(([name, value]) => `${name}: ${value};`)
    .join(' ');

/**
 * Tokens on our own wrapper, never on the host: custom properties inherit into a shadow tree, and the page
 * could otherwise override them by styling the host element.
 */
export function tokenCss(selector: string): string {
  return `${selector} { ${declarations(LIGHT)} color-scheme: light; }
@media (prefers-color-scheme: dark) { ${selector}:not([data-theme='light']) { ${declarations(DARK)} color-scheme: dark; } }
${selector}[data-theme='dark'] { ${declarations(DARK)} color-scheme: dark; }`;
}
