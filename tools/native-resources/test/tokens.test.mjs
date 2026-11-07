import assert from 'node:assert/strict';
import { test } from 'node:test';
import { argb, fontFamilies, parseColor, parseCubicBezier, parseLinearGradient, parseRules, quantize, resolveVars, toMilliseconds, toPoints } from '../lib/css.mjs';
import { buildTokens, kotlinTokens, swiftTokens, tokenName } from '../lib/tokens.mjs';

const near = (actual, expected) => {
  for (const k of Object.keys(expected)) assert.ok(Math.abs(actual[k] - expected[k]) < 1e-9, `${k}: ${actual[k]} ≠ ${expected[k]}`);
};

test('colours: hex in every length', () => {
  assert.deepEqual(parseColor('#2456F0'), { r: 0x24, g: 0x56, b: 0xf0, a: 1 });
  assert.deepEqual(parseColor('#fff'), { r: 255, g: 255, b: 255, a: 1 });
  near(parseColor('#0008'), { r: 0, g: 0, b: 0, a: 0x88 / 255 });
  near(parseColor('#11223380'), { r: 0x11, g: 0x22, b: 0x33, a: 0x80 / 255 });
  assert.equal(parseColor('1rem'), null);
});

test('colours: rgb() and rgba(), space and comma syntax, alpha as number or %', () => {
  assert.deepEqual(parseColor('rgb(11 18 32 / 0.045)'), { r: 11, g: 18, b: 32, a: 0.045 });
  assert.deepEqual(parseColor('rgb(255 255 255 / 5%)'), { r: 255, g: 255, b: 255, a: 0.05 });
  assert.deepEqual(parseColor('rgba(0, 0, 0, 0.6)'), { r: 0, g: 0, b: 0, a: 0.6 });
  assert.deepEqual(parseColor('rgb(1, 2, 3)'), { r: 1, g: 2, b: 3, a: 1 });
  near(parseColor('rgb(100% 0% 50%)'), { r: 255, g: 0, b: 127.5, a: 1 });
});

test('colours: color-mix in srgb, premultiplied', () => {
  // With transparent: the same colour at that alpha.
  near(parseColor('color-mix(in srgb, #2456f0 11%, transparent)'), { r: 0x24, g: 0x56, b: 0xf0, a: 0.11 });
  // Two opaque colours: a straight blend; the second's share is what's left.
  near(parseColor('color-mix(in srgb, #000000 25%, #ffffff)'), { r: 191.25, g: 191.25, b: 191.25, a: 1 });
  // No percentages: half and half.
  near(parseColor('color-mix(in srgb, #ff0000, #0000ff)'), { r: 127.5, g: 0, b: 127.5, a: 1 });
  // Percentages under 100% scale the alpha.
  near(parseColor('color-mix(in srgb, #ff0000 30%, #0000ff 20%)'), { r: 153, g: 0, b: 102, a: 0.5 });
  assert.throws(() => parseColor('color-mix(in oklch, red, blue)'), /in srgb/);
});

test('colours: var() resolved in the right theme, quantised, ARGB', () => {
  const vars = new Map([
    ['--trust', '#5c86ff'],
    ['--selected', 'color-mix(in srgb, var(--trust) 20%, transparent)'],
  ]);
  const selected = quantize(parseColor(resolveVars(vars.get('--selected'), vars)));
  assert.deepEqual(selected, { rgb: 0x5c86ff, alpha: 0.2 });
  assert.equal(argb(selected), 0x335c86ff);
  assert.equal(argb({ rgb: 0x2456f0, alpha: 1 }), 0xff2456f0);
  assert.equal(argb({ rgb: 0x0b1220, alpha: 0.045 }), 0x0b0b1220);
  assert.throws(() => resolveVars('var(--nope)', vars), /--nope isn't defined/);
});

test('gradients: angle and stops, missing locations spread evenly', () => {
  const g = parseLinearGradient('linear-gradient(120deg, #2456f0 0%, #1a86c8 50%, #10b77f 100%)');
  assert.equal(g.angle, 120);
  assert.deepEqual(
    g.stops.map((s) => s.location),
    [0, 0.5, 1],
  );
  assert.deepEqual(
    parseLinearGradient('linear-gradient(0.25turn, #f00, #fff, #00f)').stops.map((s) => s.location),
    [0, 0.5, 1],
  );
  assert.equal(parseLinearGradient('linear-gradient(0.25turn, #000, #fff)').angle, 90);
});

test('lengths: rem → points at 16 per rem, clamp() takes its minimum', () => {
  assert.equal(toPoints('0.9375rem'), 15);
  assert.equal(toPoints('1.0625rem'), 17);
  assert.equal(toPoints('12px'), 12);
  assert.equal(toPoints('clamp(1.6rem, 1.3rem + 1.2vw, 2.1rem)'), 25.6);
  assert.throws(() => toPoints('2vw'), /Not a length/);
});

test('motion, easing and fonts', () => {
  assert.equal(toMilliseconds('140ms'), 140);
  assert.equal(toMilliseconds('0.5s'), 500);
  assert.equal(toMilliseconds('#fff'), null);
  assert.deepEqual(parseCubicBezier('cubic-bezier(0.34, 1.4, 0.64, 1)'), [0.34, 1.4, 0.64, 1]);
  assert.deepEqual(fontFamilies("'Mona Sans Variable', 'Mona Sans', 'Noto Sans Arabic Variable', ui-sans-serif, system-ui"), ['Mona Sans', 'Noto Sans Arabic']);
  assert.equal(tokenName('2xl'), 'xl2');
  assert.equal(tokenName('line-strong'), 'lineStrong');
});

const CSS = `
/* comment { with braces } */
:root {
  --trust: #2456f0;
  --button: #2456f0;
  --selected: color-mix(in srgb, var(--trust) 11%, transparent);
  --gradient: linear-gradient(120deg, var(--trust) 0%, #10b77f 100%);
  --hover: rgb(11 18 32 / 0.045);
  --shadow: 0 1px 2px rgb(11 18 32 / 0.06);
  --font-sans: 'Mona Sans Variable', 'Mona Sans', sans-serif;
  --text-md: 0.9375rem;
  --text-2xl: clamp(1.6rem, 1.3rem + 1.2vw, 2.1rem);
  --radius: 0.75rem;
  --radius-sm: 0.5rem;
  --ease-out: cubic-bezier(0.2, 0.7, 0.2, 1);
  --fast: 140ms;
  color-scheme: light;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme='light']) {
    --trust: #5c86ff;
    --hover: rgb(255 255 255 / 0.05);
  }
}
:root[data-theme='dark'] {
  --trust: #5c86ff;
  --hover: rgb(255 255 255 / 0.05);
}
`;

test('rules: nested at-rules keep their path', () => {
  const rules = parseRules(CSS);
  assert.deepEqual(
    rules.map((r) => r.path),
    [[':root'], ['@media (prefers-color-scheme: dark)', ":root:not([data-theme='light'])"], ['@media (prefers-color-scheme: dark)'], [":root[data-theme='dark']"]],
  );
  assert.equal(rules[0].declarations.get('--fast'), '140ms');
});

test('tokens: light and dark, each kind sorted out, unknown tokens refused', () => {
  const model = buildTokens(CSS);
  const color = (name) => model.colors.find((c) => c.name === name);
  assert.deepEqual(color('trust').dark, { rgb: 0x5c86ff, alpha: 1 });
  assert.deepEqual(color('button').dark, { rgb: 0x2456f0, alpha: 1 }); // not overridden: the light value
  assert.deepEqual(color('selected').dark, { rgb: 0x5c86ff, alpha: 0.11 }); // var() resolved in the dark theme
  assert.deepEqual(model.gradients[0].stops[0].dark, { rgb: 0x5c86ff, alpha: 1 });
  assert.deepEqual(model.skipped, ['--shadow']);
  assert.deepEqual(
    model.typeScale.map((t) => [t.name, t.points, t.fluid]),
    [
      ['md', 15, false],
      ['xl2', 25.6, true],
    ],
  );
  assert.deepEqual(
    model.radii.map((r) => [r.name, r.points]),
    [
      ['base', 12],
      ['sm', 8],
    ],
  );
  assert.deepEqual(model.fonts[0].families, ['Mona Sans']);
  assert.throws(() => buildTokens(CSS.replace('--fast: 140ms;', '--fast: 140ms; --weird: 3;')), /--weird: 3 isn't a token/);
  assert.throws(() => buildTokens(CSS.replace("--hover: rgb(255 255 255 / 0.05);\n  }", '--hover: #000;\n  }')), /differ/);
});

test('tokens: Swift and Kotlin output', () => {
  const model = buildTokens(CSS);
  const swift = swiftTokens(model);
  assert.match(swift, /public static let selected = ThemedColor\(light: RGBA\(0x2456F0, alpha: 0\.11\), dark: RGBA\(0x5C86FF, alpha: 0\.11\)\)/);
  assert.match(swift, /public static let xl2: CGFloat = 25\.6/);
  assert.match(swift, /public static let fast: TimeInterval = 0\.14/);
  assert.match(swift, /UIColor \{ \$0\.userInterfaceStyle == \.dark \? dark : light \}/);
  const kotlin = kotlinTokens(model);
  assert.match(kotlin, /const val hover: Long = 0x0B0B1220L/);
  assert.match(kotlin, /const val hover: Long = 0x0DFFFFFFL/);
  assert.match(kotlin, /const val fastMillis: Int = 140/);
  assert.match(kotlin, /val easeOut = CubicBezier\(0\.2f, 0\.7f, 0\.2f, 1f\)/);
});
