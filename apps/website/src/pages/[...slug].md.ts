// Markdown twin of every docs page: /docs/security/encryption/ → /docs/security/encryption.md
import type { APIRoute, GetStaticPaths } from 'astro';
import { getCollection, type CollectionEntry } from 'astro:content';
import { SITE_NAME, SITE_URL } from '../site.config';

export const getStaticPaths = (async () => {
  const docs = await getCollection('docs');
  return docs.map((entry) => ({ params: { slug: entry.id }, props: { entry } }));
}) satisfies GetStaticPaths;

export const GET: APIRoute<{ entry: CollectionEntry<'docs'> }> = ({ props: { entry } }) => {
  const { title, description, status } = entry.data;
  const url = new URL(`/${entry.id}/`, SITE_URL).href;
  const header = [
    `# ${title}`,
    '',
    `> ${description ?? ''}`,
    '',
    `Source: ${url}`,
    `Status: ${status}`,
    `Project: ${SITE_NAME}`,
    '',
  ].join('\n');
  // Root-relative links become absolute so the Markdown stands on its own outside the site.
  const body = (entry.body ?? '').replace(/\]\(\/(?!\/)/g, `](${SITE_URL}/`);
  return new Response(`${header}\n${body}`.trimEnd() + '\n', {
    headers: { 'Content-Type': 'text/markdown; charset=utf-8' },
  });
};
