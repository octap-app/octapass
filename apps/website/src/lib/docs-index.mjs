// Builds the per-page link index that goes into /llms.txt (llmstxt.org: H2 sections of links),
// and the sidebar's links for each docs section.
// Runs at config time, so it reads the repo-root docs/ folder directly instead of the content collection.
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';

const field = (frontmatter, name) => {
  const match = frontmatter.match(new RegExp(`^\\s*${name}:\\s*(.+)$`, 'm'));
  return match ? match[1].trim().replace(/^['"]|['"]$/g, '') : undefined;
};

const LOCALE_DIRS = new Set(['ar']);

function walk(dir, root = dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    // Translations live in docs/<language>/; the index lists the English pages.
    if (entry.isDirectory()) return dir === root && LOCALE_DIRS.has(entry.name) ? [] : walk(path, root);
    return /\.mdx?$/.test(entry.name) && !entry.name.startsWith('_') ? [path] : [];
  });
}

/** Every English docs page with the front matter the index and the sidebar use. */
function readPages(docsDir) {
  return walk(docsDir).map((file) => {
    const rel = relative(docsDir, file).replace(/\\/g, '/');
    const frontmatter = readFileSync(file, 'utf8').match(/^---\n([\s\S]*?)\n---/)?.[1] ?? '';
    const slug = rel.replace(/\.mdx?$/, '').replace(/(^|\/)index$/, '');
    return {
      folder: slug.includes('/') ? slug.split('/')[0] : '',
      title: field(frontmatter, 'title') ?? slug,
      description: field(frontmatter, 'description') ?? '',
      status: field(frontmatter, 'status') ?? 'planned',
      order: Number(field(frontmatter, 'order') ?? 999),
      slug,
    };
  });
}

const byOrder = (a, b) => a.order - b.order || a.title.localeCompare(b.title);

/**
 * The sidebar items for one docs section, as `slug` links in `sidebar.order`, then title, order.
 * Starlight's `autogenerate` can't be used: it matches pages by file path under `src/content/docs`,
 * and these pages are loaded from the repo-root docs/ folder, so every group came out empty.
 * A `slug` link takes its label from the page, so Arabic pages get their own titles.
 * @param {string} docsDir absolute path to the docs folder
 * @param {string} folder the section's folder, e.g. `features`
 */
export function buildSidebarItems(docsDir, folder) {
  return readPages(docsDir)
    .filter((p) => p.folder === folder)
    .sort(byOrder)
    .map((p) => ({ slug: `docs/${p.slug}` }));
}

/**
 * @param {string} docsDir absolute path to the docs folder
 * @param {string} siteUrl
 * @param {Array<[string, string]>} sections [label, folder] pairs in sidebar order
 */
export function buildDocsIndex(docsDir, siteUrl, sections) {
  const pages = readPages(docsDir).map((p) => ({ ...p, url: new URL(p.slug ? `/docs/${p.slug}.md` : '/docs.md', siteUrl).href }));

  const line = (p) => `- [${p.title}](${p.url}): ${p.description} (status: ${p.status})`;
  return [['Introduction', ''], ...sections]
    .map(([label, folder]) => {
      const items = pages.filter((p) => p.folder === folder).sort(byOrder);
      return items.length ? `## ${label}\n\n${items.map(line).join('\n')}` : '';
    })
    .filter(Boolean)
    .join('\n\n');
}
