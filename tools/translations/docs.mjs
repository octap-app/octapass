// Reading docs pages: headings, links and front matter, shared by the checker and the anchor fixer.
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { createRequire } from 'node:module';

// The same slugger the site uses for heading ids, so anchors here match the built pages.
const require = createRequire(new URL('../../apps/website/package.json', import.meta.url));
const { default: GithubSlugger } = await import(require.resolve('github-slugger'));

export function walk(dir, skip = () => false) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (skip(path)) return [];
    if (entry.isDirectory()) return walk(path, skip);
    return /\.mdx?$/.test(entry.name) ? [path] : [];
  });
}

export const relativePath = (root, file) => relative(root, file).replace(/\\/g, '/');

/** The page's lines outside fenced code. */
export function proseLines(text) {
  let fence = null;
  return text.split('\n').map((line) => {
    const mark = line.match(/^\s*(```+|~~~+)/)?.[1];
    if (mark && (!fence || mark.startsWith(fence))) {
      fence = fence ? null : mark;
      return '';
    }
    return fence ? '' : line;
  });
}

const stripInline = (text) =>
  text
    .replace(/`([^`]*)`/g, '$1')
    .replace(/\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(/\*\*?|__/g, '')
    .trim();

/** Headings in order, with the ids the site gives them. */
export function headings(text) {
  const slugger = new GithubSlugger();
  return proseLines(text).flatMap((line) => {
    const match = line.match(/^(#{2,6})\s+(.+?)\s*$/);
    if (!match) return [];
    const plain = stripInline(match[2]);
    return [{ level: match[1].length, text: plain, id: slugger.slug(plain) }];
  });
}

export const frontMatter = (text) => text.match(/^---\n([\s\S]*?)\n---/)?.[1] ?? '';
export const field = (fm, name) => fm.match(new RegExp(`^${name}:\\s*(.+)$`, 'm'))?.[1]?.trim();
export const sidebarOrder = (fm) => fm.match(/^sidebar:\n\s+order:\s*(\S+)/m)?.[1];

export const fenced = (text) => text.match(/^\s*(```+|~~~+)[^\n]*\n[\s\S]*?^\s*\1\s*$/gm) ?? [];

/** Markdown links outside code. `url` is the target, `index` its offset in the text. */
export function links(text) {
  const lines = proseLines(text);
  const found = [];
  let offset = 0;
  const raw = text.split('\n');
  raw.forEach((line, i) => {
    const prose = lines[i];
    for (const match of prose.matchAll(/\]\(([^)\s]+)\)/g)) found.push({ url: match[1], index: offset + match.index + 2 });
    offset += line.length + 1;
  });
  return found;
}

/** Path of the docs file for a site URL path, without language: /docs/a/b/ → a/b.md. */
export function fileForPage(url) {
  const path = url.replace(/^\/(?:ar\/)?docs\/?/, '').replace(/\/$/, '');
  return path ? `${path}.md` : 'index.md';
}
