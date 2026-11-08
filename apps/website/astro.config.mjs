// @ts-check
import { defineConfig } from 'astro/config';
import sitemap from '@astrojs/sitemap';
import starlight from '@astrojs/starlight';
import starlightLlmsTxt from 'starlight-llms-txt';
import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { REPO_URL, SITE_DESCRIPTION, SITE_NAME, SITE_URL, VAULT_URL } from './src/site.config.ts';
import { buildDocsIndex, buildSidebarItems } from './src/lib/docs-index.mjs';
import { BUILD_DATE, docsSourceMap, gitDate, newest } from './src/lib/lastmod.mjs';

const sections = [
  ['Getting started', 'getting-started', 'البدء'],
  ['Features', 'features', 'الميزات'],
  ['Import & export', 'import-export', 'الاستيراد والتصدير'],
  ['Platforms', 'platforms', 'المنصات'],
  ['Security', 'security', 'الأمان'],
  ['Self-hosting', 'self-hosting', 'الاستضافة الذاتية'],
  ['Developers', 'developers', 'المطورون'],
  ['Contributing', 'contributing', 'المساهمة'],
  ['Reference', 'reference', 'المرجع'],
];
const docsDir = fileURLToPath(new URL('../../docs', import.meta.url));
const docsIndex = buildDocsIndex(docsDir, SITE_URL, sections);

// Changelog entries by slug, newest first, from their front matter (the website's changelog collection reads the same files).
const changelogDir = fileURLToPath(new URL('../../changelog', import.meta.url));
const changelog = readdirSync(changelogDir)
  .filter((name) => /^[0-9].*\.md$/.test(name))
  .map((name) => {
    const frontmatter = readFileSync(`${changelogDir}/${name}`, 'utf8').match(/^---\n([\s\S]*?)\n---/)?.[1] ?? '';
    const field = (key) => frontmatter.match(new RegExp(`^${key}:\\s*(.+)$`, 'm'))?.[1].trim().replace(/^['"]|['"]$/g, '');
    return { slug: name.replace(/\.md$/, ''), date: field('date'), title: field('title'), summary: field('summary') };
  })
  .sort((a, b) => (b.date ?? '').localeCompare(a.date ?? '') || b.slug.localeCompare(a.slug));

// <lastmod> for each sitemap URL: the last commit to the page's source (src/lib/lastmod.mjs), a changelog
// entry's own date, or the build date when neither is known.
const docsSources = docsSourceMap();
const landingDate = (locale) =>
  newest(gitDate('apps/website/src/components/Landing.astro'), gitDate(`apps/website/src/i18n/landing/${locale}.json`), gitDate('apps/website/src/site.config.ts'));
const changelogDates = new Map(changelog.map((entry) => [`/changelog/${entry.slug}/`, entry.date]));
function lastmodFor(pathname) {
  if (pathname === '/') return landingDate('en');
  if (pathname === '/ar/') return landingDate('ar');
  if (pathname === '/changelog/') return changelog[0]?.date;
  if (changelogDates.has(pathname)) return changelogDates.get(pathname);
  if (docsSources.has(pathname)) return gitDate(docsSources.get(pathname));
  return undefined;
}

// What /llms.txt lists besides the docs: the site's other pages, as Markdown.
const md = (path) => new URL(path, SITE_URL).href;
const sitePagesIndex = [
  '## Site pages',
  '',
  `- [Home](${md('/index.md')}): What ${SITE_NAME} is, its features, the free plan, every platform and whether it's available yet, open source links and the FAQ`,
  `- [Home, in Arabic](${md('/ar/index.md')}): The same page in Arabic`,
  `- [Changelog](${md('/changelog/index.md')}): Every notable change, newest first, with links to each entry's Markdown`,
  ...changelog.slice(0, 10).map((entry) => `- [${entry.title}](${md(`/changelog/${entry.slug}.md`)}): ${entry.date}. ${entry.summary}`),
].join('\n');

export default defineConfig({
  site: SITE_URL,
  trailingSlash: 'ignore',
  integrations: [
    // Configured here rather than left to Starlight, which only adds hreflang alternates.
    sitemap({
      i18n: { defaultLocale: 'root', locales: { root: 'en', ar: 'ar' } },
      filter: (page) => !/\/404\/?$/.test(new URL(page).pathname),
      serialize(item) {
        item.lastmod = lastmodFor(new URL(item.url).pathname) ?? BUILD_DATE;
        // The links array is shared by every language version of a page, so copy it before adding x-default.
        const en = item.links?.find((link) => link.lang === 'en');
        if (en) item.links = [...item.links, { lang: 'x-default', url: en.url }];
        return item;
      },
    }),
    starlight({
      title: SITE_NAME,
      description: SITE_DESCRIPTION,
      logo: { light: './src/assets/logo.svg', dark: './src/assets/logo-dark.svg', alt: 'Octa Pass' },
      favicon: '/favicon.svg',
      // English stays at the site root; Arabic is /ar/docs/… from docs/ar/. A page with no translation shows the English text with a notice.
      defaultLocale: 'root',
      locales: {
        root: { label: 'English', lang: 'en' },
        ar: { label: 'العربية', lang: 'ar', dir: 'rtl' },
      },
      // Apply Starlight's Markdown features (asides, heading links) to the repo-root docs folder.
      markdown: { processedDirs: ['../../docs'] },
      disable404Route: true, // branded 404 lives in src/pages/404.astro
      social: [{ icon: 'github', label: 'Source code', href: REPO_URL }],
      // Docs live in the repo-root /docs folder; the `..` segments resolve to it in the edit URL.
      editLink: { baseUrl: `${REPO_URL}/edit/main/apps/website/` },
      customCss: [
        '@fontsource-variable/mona-sans/wdth.css',
        '@fontsource/monaspace-neon/400.css',
        '@fontsource/monaspace-neon/600.css',
        '@fontsource-variable/noto-sans-arabic/wght.css',
        './src/styles/starlight.css',
      ],
      components: {
        Head: './src/components/Head.astro',
        PageTitle: './src/components/PageTitle.astro',
      },
      head: [
        { tag: 'meta', attrs: { name: 'theme-color', content: '#000000' } },
        { tag: 'link', attrs: { rel: 'apple-touch-icon', href: '/apple-touch-icon.png' } },
      ],
      sidebar: [
        { label: 'Introduction', translations: { ar: 'مقدمة' }, link: '/docs/' },
        ...sections.map(([label, folder, ar]) => ({ label, translations: { ar }, items: buildSidebarItems(docsDir, folder) })),
      ],
      plugins: [
        starlightLlmsTxt({
          projectName: SITE_NAME,
          description: SITE_DESCRIPTION,
          details: [
            `${SITE_NAME} is a free, open-source (MIT licence) password manager with end-to-end encryption: the vault is encrypted on the device, and the server only stores ciphertext. Source code: ${REPO_URL}. Website: ${SITE_URL}.`,
            `Project status: public alpha. The hosted service is open for sign-ups in the web vault at ${VAULT_URL}. The apps are built but not in any app store yet, and nothing has had its external audit. Pages carry a \`status\` of planned, in-progress, beta or stable.`,
            'The docs are also in Arabic under `/ar/docs/`. This index lists the English pages.',
            'Every docs page is also available as raw Markdown by appending `.md` to its URL path, e.g. `/docs/security/encryption.md`. So are the home page (`/index.md`, `/ar/index.md`), the changelog (`/changelog/index.md`) and each changelog entry (`/changelog/<slug>.md`).',
            'An agent skill for querying these docs is published at `/skills/octapass-docs/SKILL.md`, and one for using the `octapass` command-line tool safely at `/skills/octapass-cli/SKILL.md`.',
            sitePagesIndex,
            docsIndex,
          ].join('\n\n'),
          optionalLinks: [
            { label: 'Changelog', url: `${SITE_URL}/changelog/`, description: 'Dated project changes' },
            { label: 'Agent skill', url: `${SITE_URL}/skills/octapass-docs/SKILL.md`, description: 'Skill that teaches AI agents to search and cite these docs' },
            { label: 'Web vault', url: VAULT_URL, description: 'The hosted service, open as a public alpha' },
            { label: 'CLI agent skill', url: `${SITE_URL}/skills/octapass-cli/SKILL.md`, description: 'Skill that teaches AI agents to use the octapass CLI without exposing secrets' },
            { label: 'Source code', url: REPO_URL, description: 'MIT monorepo' },
          ],
          promote: ['docs', 'docs/getting-started/**', 'docs/security/**'],
          demote: ['docs/contributing/**', 'docs/reference/glossary'],
        }),
      ],
    }),
  ],
  vite: {
    server: { fs: { allow: ['../..'] } },
  },
});
