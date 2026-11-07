import { defineCollection, z } from 'astro:content';
import { glob } from 'astro/loaders';
import { docsSchema, i18nSchema } from '@astrojs/starlight/schema';
import { i18nLoader } from '@astrojs/starlight/loaders';

// Docs live in the repo-root `/docs` folder so they stay readable on GitHub and by AI agents,
// and are served by the website under `/docs/`.
// A translation lives in docs/<locale>/ and gets the id Starlight expects: docs/ar/security/encryption.md
// becomes ar/docs/security/encryption, served at /ar/docs/security/encryption/.
const slugFromPath = (entry: string) => {
  const path = entry.replace(/\.(md|mdx)$/, '').replace(/(^|\/)index$/, '');
  const [, locale, rest] = path.match(/^(ar)(?:\/(.*))?$/) ?? [];
  if (locale) return rest ? `${locale}/docs/${rest}` : `${locale}/docs`;
  return path ? `docs/${path}` : 'docs';
};

export const collections = {
  i18n: defineCollection({ loader: i18nLoader(), schema: i18nSchema() }),
  docs: defineCollection({
    loader: glob({
      base: '../../docs',
      pattern: '**/[^_]*.{md,mdx}',
      generateId: ({ entry }) => slugFromPath(entry),
    }),
    schema: docsSchema({
      extend: z.object({
        // Lifecycle of the feature a page describes.
        status: z.enum(['planned', 'in-progress', 'beta', 'stable']).default('planned'),
      }),
    }),
  }),
  changelog: defineCollection({
    loader: glob({ base: '../../changelog', pattern: '[0-9]*.md' }),
    schema: z.object({
      title: z.string(),
      date: z.coerce.date(),
      summary: z.string(),
      tags: z.array(z.string()).default([]),
    }),
  }),
};
