// Reads and patches the TypeScript message catalogs without running them. A catalog is an object
// literal of string literals and nested objects (`export const en = { … }`), so a small scanner is
// enough, and it can report where each string sits so a fix changes only that string.

const PLURAL_FORMS = new Set(['zero', 'one', 'two', 'few', 'many', 'other']);

export const COMPONENTS = [
  { name: 'web', en: { file: 'apps/web/src/i18n/en.ts', start: 'export const en = {' }, ar: { file: 'apps/web/src/i18n/ar.ts', start: 'export const ar: Translation<typeof en> = {' } },
  { name: 'extension', en: { file: 'apps/extension/src/i18n.ts', start: 'const en = {' }, ar: { file: 'apps/extension/src/i18n.ts', start: 'const ar: Translation<typeof en> = {' } },
  { name: 'desktop', en: { file: 'apps/desktop/src/i18n.ts', start: 'const en = {' }, ar: { file: 'apps/desktop/src/i18n.ts', start: 'const ar: Translation<typeof en> = {' } },
  { name: 'phone', en: { file: 'apps/web/src/i18n/phone.ts', start: 'const en = {' }, ar: { file: 'apps/web/src/i18n/phone.ts', start: 'const ar: Translation<typeof en> = {' } },
];

class Scanner {
  constructor(text, at) {
    this.text = text;
    this.at = at;
  }

  fail(message) {
    const line = this.text.slice(0, this.at).split('\n').length;
    throw new Error(`line ${line}: ${message}`);
  }

  skip() {
    for (;;) {
      const rest = this.text.slice(this.at, this.at + 2);
      if (/^\s/.test(rest)) this.at += 1;
      else if (rest === '//') this.at = this.text.indexOf('\n', this.at);
      else if (rest === '/*') this.at = this.text.indexOf('*/', this.at) + 2;
      else return;
    }
  }

  string() {
    const quote = this.text[this.at];
    const start = this.at;
    this.at += 1;
    let value = '';
    for (;;) {
      const c = this.text[this.at];
      if (c === undefined) this.fail('unterminated string');
      if (c === quote) break;
      if (quote === '`' && c === '$' && this.text[this.at + 1] === '{') this.fail('template with a substitution');
      if (c === '\\') {
        const next = this.text[this.at + 1];
        const escapes = { n: '\n', t: '\t', r: '\r' };
        if (next === 'u') {
          value += String.fromCharCode(parseInt(this.text.slice(this.at + 2, this.at + 6), 16));
          this.at += 6;
          continue;
        }
        value += escapes[next] ?? next;
        this.at += 2;
        continue;
      }
      value += c;
      this.at += 1;
    }
    this.at += 1;
    return { value, start, end: this.at };
  }

  key() {
    const c = this.text[this.at];
    if (c === "'" || c === '"') return this.string().value;
    const match = this.text.slice(this.at).match(/^[A-Za-z_$][\w$]*/);
    if (!match) this.fail('expected a key');
    this.at += match[0].length;
    return match[0];
  }

  object(path, spans) {
    if (this.text[this.at] !== '{') this.fail('expected {');
    this.at += 1;
    const out = {};
    for (;;) {
      this.skip();
      if (this.text[this.at] === '}') {
        this.at += 1;
        return out;
      }
      const key = this.key();
      this.skip();
      if (this.text[this.at] !== ':') this.fail(`expected : after ${key}`);
      this.at += 1;
      this.skip();
      const next = [...path, key];
      if (this.text[this.at] === '{') out[key] = this.object(next, spans);
      else if ("'\"`".includes(this.text[this.at])) {
        const { value, start, end } = this.string();
        out[key] = value;
        spans.set(next.join('\0'), { start, end });
      } else this.fail(`${next.join('.')} isn't a string or object`);
      this.skip();
      if (this.text[this.at] === ',') this.at += 1;
    }
  }
}

/** The catalog starting at `start`, and where each string sits in `text`. */
export function parseCatalog(text, start) {
  const at = text.indexOf(start);
  if (at < 0) throw new Error(`can't find "${start}"`);
  const spans = new Map();
  const scanner = new Scanner(text, at + start.length - 1);
  return { catalog: scanner.object([], spans), spans };
}

const isPlural = (value) => Object.keys(value).every((key) => PLURAL_FORMS.has(key));

/** Nested catalog → i18next v4 JSON: plural groups become `key_one`, `key_other`. */
export function toI18next(catalog) {
  const out = {};
  for (const [key, value] of Object.entries(catalog)) {
    if (typeof value === 'string') out[key] = value;
    else if (isPlural(value)) for (const [form, text] of Object.entries(value)) out[`${key}_${form}`] = text;
    else out[key] = toI18next(value);
  }
  return out;
}

/** Patches `catalog`'s strings in `text` from i18next JSON. Only strings that exist are touched. */
export function patchCatalog(text, start, translated) {
  const { catalog, spans } = parseCatalog(text, start);
  const changes = [];
  const visit = (node, json, path) => {
    for (const [key, value] of Object.entries(node)) {
      const next = [...path, key];
      if (typeof value === 'string') {
        const updated = json?.[key];
        if (typeof updated === 'string' && updated !== value) changes.push({ ...spans.get(next.join('\0')), updated });
      } else if (isPlural(value)) {
        for (const [form, old] of Object.entries(value)) {
          const updated = json?.[`${key}_${form}`];
          if (typeof updated === 'string' && updated !== old) changes.push({ ...spans.get([...next, form].join('\0')), updated });
        }
      } else visit(value, json?.[key], next);
    }
  };
  visit(catalog, translated, []);
  let out = text;
  for (const { start: from, end, updated } of changes.sort((a, b) => b.start - a.start)) {
    const literal = `'${updated.replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\n/g, '\\n')}'`;
    out = out.slice(0, from) + literal + out.slice(end);
  }
  return { text: out, changed: changes.length };
}
