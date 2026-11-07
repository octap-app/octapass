// Just enough CSS for packages/ui/src/styles/tokens.css: custom properties per rule, colours
// (hex, rgb()/rgba(), color-mix() in srgb, transparent), gradients, lengths, durations, easings.

/** Rules with their selector path (at-rules outside in) and `--custom: value` declarations. */
export function parseRules(css) {
  const text = css.replace(/\/\*[\s\S]*?\*\//g, '');
  const rules = [];
  const stack = [];
  let start = 0;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === '{') {
      // Up to the last `;` is the open rule's declarations; the rest is the new rule's selector.
      const chunk = text.slice(start, i);
      const cut = chunk.lastIndexOf(';') + 1;
      if (stack.length) stack.at(-1).body += chunk.slice(0, cut);
      stack.push({ selector: chunk.slice(cut).trim().replace(/\s+/g, ' '), body: '' });
      start = i + 1;
    } else if (ch === '}') {
      const rule = stack.pop();
      if (!rule) throw new Error('Unbalanced } in CSS');
      rule.body += text.slice(start, i);
      start = i + 1;
      const declarations = new Map();
      for (const decl of splitTop(rule.body, ';')) {
        const m = /^\s*(--[\w-]+)\s*:\s*([\s\S]+?)\s*$/.exec(decl);
        if (m) declarations.set(m[1], m[2].replace(/\s+/g, ' '));
      }
      rules.push({ path: [...stack.map((r) => r.selector), rule.selector], declarations });
    }
  }
  if (stack.length) throw new Error('Unbalanced { in CSS');
  return rules;
}

/** Splits on `sep` outside parentheses. */
export function splitTop(value, sep = ',') {
  const parts = [];
  let depth = 0;
  let current = '';
  for (const ch of value) {
    if (ch === '(') depth++;
    if (ch === ')') depth--;
    if (ch === sep && depth === 0) {
      parts.push(current);
      current = '';
    } else current += ch;
  }
  if (current.trim()) parts.push(current);
  return parts.map((p) => p.trim()).filter(Boolean);
}

/** `var(--x)` replaced by its value from `vars`, recursively. */
export function resolveVars(value, vars, seen = new Set()) {
  return value.replace(/var\(\s*(--[\w-]+)\s*(?:,\s*([^)]*))?\)/g, (_, name, fallback) => {
    if (seen.has(name)) throw new Error(`${name} refers to itself`);
    const v = vars.get(name) ?? fallback;
    if (v === undefined) throw new Error(`${name} isn't defined`);
    return resolveVars(v, vars, new Set([...seen, name]));
  });
}

// Colours: { r, g, b } 0–255 (may be fractional after mixing), a 0–1. -------------------------------

const NAMED = { transparent: [0, 0, 0, 0], black: [0, 0, 0, 1], white: [255, 255, 255, 1] };

const number = (s) => {
  if (!/^[+-]?(\d+\.?\d*|\.\d+)(e[+-]?\d+)?%?$/i.test(s)) throw new Error(`Not a number: ${s}`);
  return Number.parseFloat(s);
};
const channel = (s) => (s.endsWith('%') ? (number(s) / 100) * 255 : number(s));
const alpha = (s) => (s.endsWith('%') ? number(s) / 100 : number(s));

/** A CSS colour, or null if `value` isn't one. */
export function parseColor(value) {
  const v = value.trim().toLowerCase();
  if (v in NAMED) {
    const [r, g, b, a] = NAMED[v];
    return { r, g, b, a };
  }
  let m = /^#([0-9a-f]{3,4}|[0-9a-f]{6}|[0-9a-f]{8})$/.exec(v);
  if (m) {
    let hex = m[1];
    if (hex.length <= 4) hex = [...hex].map((c) => c + c).join('');
    const n = (i) => Number.parseInt(hex.slice(i, i + 2), 16);
    return { r: n(0), g: n(2), b: n(4), a: hex.length === 8 ? n(6) / 255 : 1 };
  }
  m = /^rgba?\((.*)\)$/.exec(v);
  if (m) {
    const inner = m[1].trim();
    let parts;
    let a = '1';
    if (inner.includes(',')) {
      parts = inner.split(',').map((s) => s.trim());
      if (parts.length === 4) a = parts.pop();
    } else {
      const [rgb, slashAlpha] = inner.split('/').map((s) => s.trim());
      parts = rgb.split(/\s+/);
      if (slashAlpha !== undefined) a = slashAlpha;
    }
    if (parts.length !== 3) throw new Error(`Bad colour: ${value}`);
    return { r: channel(parts[0]), g: channel(parts[1]), b: channel(parts[2]), a: alpha(a) };
  }
  m = /^color-mix\((.*)\)$/.exec(v);
  if (m) return colorMix(m[1], value);
  return null;
}

/**
 * `color-mix(in srgb, A p%, B q%)` per CSS Color 5: percentages normalised to 100% (a sum under 100%
 * also scales alpha), channels mixed premultiplied by alpha. So mixing with `transparent` keeps the
 * colour and scales its alpha.
 */
function colorMix(inner, original) {
  const [space, first, second] = splitTop(inner);
  if (space !== 'in srgb' || !second) throw new Error(`Only color-mix(in srgb, a, b) is supported: ${original}`);
  const part = (s) => {
    const m = /^(.*?)(?:\s+([\d.]+%))?$/.exec(s);
    const color = parseColor(m[1]);
    if (!color) throw new Error(`Bad colour in ${original}`);
    return { color, p: m[2] === undefined ? undefined : number(m[2]) / 100 };
  };
  const one = part(first);
  const two = part(second);
  let p1 = one.p ?? (two.p === undefined ? 0.5 : 1 - two.p);
  let p2 = two.p ?? 1 - p1;
  const sum = p1 + p2;
  if (sum <= 0) throw new Error(`color-mix percentages add up to 0: ${original}`);
  const scale = sum < 1 ? sum : 1;
  p1 /= sum;
  p2 /= sum;
  const a = one.color.a * p1 + two.color.a * p2;
  const mix = (c) => (a === 0 ? 0 : (one.color[c] * one.color.a * p1 + two.color[c] * two.color.a * p2) / a);
  return { r: mix('r'), g: mix('g'), b: mix('b'), a: a * scale };
}

/** A colour as 8-bit sRGB: `rgb` 0xRRGGBB and `alpha` 0–1 rounded to 4 places. */
export function quantize(color) {
  const c = (x) => Math.min(255, Math.max(0, Math.round(x)));
  return { rgb: (c(color.r) << 16) | (c(color.g) << 8) | c(color.b), alpha: Math.round(color.a * 10000) / 10000 };
}

/** 0xAARRGGBB, alpha rounded to a byte, as Compose's `Color(Long)` takes it. */
export function argb({ rgb, alpha }) {
  return ((Math.round(alpha * 255) << 24) >>> 0) + rgb;
}

/** `linear-gradient(120deg, #a 0%, #b 50%, #c)`: the angle in degrees and each stop's colour and 0–1 location. */
export function parseLinearGradient(value) {
  const m = /^linear-gradient\((.*)\)$/i.exec(value.trim());
  if (!m) return null;
  const parts = splitTop(m[1]);
  let angle = 180;
  const angleMatch = /^(-?[\d.]+)(deg|turn|rad)$/.exec(parts[0]);
  if (angleMatch) {
    parts.shift();
    const n = Number.parseFloat(angleMatch[1]);
    angle = angleMatch[2] === 'deg' ? n : angleMatch[2] === 'turn' ? n * 360 : (n * 180) / Math.PI;
  } else if (parts[0].startsWith('to ')) throw new Error(`Gradient direction keywords aren't supported: ${value}`);
  const stops = parts.map((p) => {
    const s = /^(.*?)(?:\s+(-?[\d.]+)%)?$/.exec(p);
    const color = parseColor(s[1]);
    if (!color) throw new Error(`Bad gradient stop: ${p}`);
    return { color, location: s[2] === undefined ? undefined : Number.parseFloat(s[2]) / 100 };
  });
  stops.forEach((stop, i) => {
    if (stop.location === undefined) stop.location = stops.length === 1 ? 0 : i / (stops.length - 1);
  });
  return { angle, stops };
}

/** `1.25rem` → 20 (points or dp, at 16 per rem); `clamp(min, …, max)` → its minimum. */
export function toPoints(value, remSize = 16) {
  const v = value.trim();
  const clamp = /^clamp\((.*)\)$/.exec(v);
  if (clamp) return toPoints(splitTop(clamp[1])[0], remSize);
  const m = /^(-?[\d.]+)(rem|px)$/.exec(v);
  if (!m) throw new Error(`Not a length in rem or px: ${value}`);
  const n = Number.parseFloat(m[1]);
  return Math.round((m[2] === 'rem' ? n * remSize : n) * 1000) / 1000;
}

/** `140ms` → 140, `0.5s` → 500. */
export function toMilliseconds(value) {
  const m = /^([\d.]+)(ms|s)$/.exec(value.trim());
  if (!m) return null;
  return Math.round(Number.parseFloat(m[1]) * (m[2] === 's' ? 1000 : 1));
}

/** `cubic-bezier(x1, y1, x2, y2)` → [x1, y1, x2, y2]. */
export function parseCubicBezier(value) {
  const m = /^cubic-bezier\((.*)\)$/.exec(value.trim());
  if (!m) return null;
  const points = m[1].split(',').map((s) => number(s.trim()));
  if (points.length !== 4) throw new Error(`Bad cubic-bezier: ${value}`);
  return points;
}

/** Quoted family names of a font stack, without fontsource's " Variable" suffix. */
export function fontFamilies(value) {
  const names = splitTop(value)
    .filter((s) => /^['"]/.test(s))
    .map((s) => s.slice(1, -1).replace(/ Variable$/, ''));
  return [...new Set(names)];
}
