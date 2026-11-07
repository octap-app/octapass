// @vitest-environment node
import { readFileSync } from 'node:fs';
import { DARK, LIGHT } from './tokens';

const css = readFileSync(new URL('../../../ui/src/styles/tokens.css', import.meta.url), 'utf8');

function block(selector: string): Map<string, string> {
  const start = css.indexOf(selector);
  const body = css.slice(css.indexOf('{', start) + 1, css.indexOf('}', start));
  const values = new Map<string, string>();
  for (const [, name, value] of body.matchAll(/(--[\w-]+):\s*([^;]+);/g)) values.set(name!, value!.trim().replace(/\s+/g, ' '));
  return values;
}

describe('inline UI tokens', () => {
  it('match the light tokens in packages/ui', () => {
    const light = block(':root {');
    for (const [name, value] of Object.entries(LIGHT)) expect([name, light.get(name)]).toEqual([name, value]);
  });

  it('match the dark tokens in packages/ui', () => {
    const dark = block(":root[data-theme='dark']");
    for (const [name, value] of Object.entries(DARK)) expect([name, dark.get(name)]).toEqual([name, value]);
  });
});
