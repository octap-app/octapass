// Markdown copy of each changelog entry: /changelog/<slug>/ → /changelog/<slug>.md
import type { APIRoute, GetStaticPaths } from 'astro';
import { getCollection, type CollectionEntry } from 'astro:content';
import { SITE_NAME, SITE_URL } from '../../site.config';

export const getStaticPaths = (async () => {
  const entries = await getCollection('changelog');
  return entries.map((entry) => ({ params: { slug: entry.id }, props: { entry } }));
}) satisfies GetStaticPaths;

export const GET: APIRoute<{ entry: CollectionEntry<'changelog'> }> = ({ props: { entry } }) => {
  const { title, summary, date, tags } = entry.data;
  const header = [
    `# ${title}`,
    '',
    `> ${summary}`,
    '',
    `Source: ${new URL(`/changelog/${entry.id}/`, SITE_URL).href}`,
    `Date: ${date.toISOString().slice(0, 10)}`,
    ...(tags.length ? [`Tags: ${tags.join(', ')}`] : []),
    `Project: ${SITE_NAME}`,
    '',
  ].join('\n');
  // Root-relative links become absolute so the Markdown stands on its own outside the site.
  const body = (entry.body ?? '').replace(/\]\(\/(?!\/)/g, `](${SITE_URL}/`);
  return new Response(`${header}\n${body}`.trimEnd() + '\n', {
    headers: { 'Content-Type': 'text/markdown; charset=utf-8' },
  });
};
