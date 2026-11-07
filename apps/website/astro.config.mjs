// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import starlightLlmsTxt from 'starlight-llms-txt';
import { fileURLToPath } from 'node:url';
import { REPO_URL, SITE_DESCRIPTION, SITE_NAME, SITE_URL, VAULT_URL } from './src/site.config.ts';
import { buildDocsIndex, buildSidebarItems } from './src/lib/docs-index.mjs';

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

export default defineConfig({
  site: SITE_URL,
  trailingSlash: 'ignore',
  integrations: [
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
            `Project status: public alpha. The hosted service is open for sign-ups in the web vault at ${VAULT_URL}. The apps are built but not in any app store yet, and nothing has had its external audit. Pages carry a \`status\` of planned, in-progress, beta or stable.`,
            'The docs are also in Arabic under `/ar/docs/`. This index lists the English pages.',
            'Every docs page is also available as raw Markdown by appending `.md` to its URL path, e.g. `/docs/security/encryption.md`.',
            'An agent skill for querying these docs is published at `/skills/octapass-docs/SKILL.md`.',
            docsIndex,
          ].join('\n\n'),
          optionalLinks: [
            { label: 'Changelog', url: `${SITE_URL}/changelog/`, description: 'Dated project changes' },
            { label: 'Agent skill', url: `${SITE_URL}/skills/octapass-docs/SKILL.md`, description: 'Skill that teaches AI agents to search and cite these docs' },
            { label: 'Web vault', url: VAULT_URL, description: 'The hosted service, open as a public alpha' },
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
