// The changelog as Markdown, for AI agents: every entry, newest first, linking to each entry's Markdown copy.
import type { APIRoute } from 'astro';
import { getCollection } from 'astro:content';
import { SITE_NAME, SITE_URL } from '../../site.config';

export const GET: APIRoute = async () => {
  const entries = (await getCollection('changelog')).sort((a, b) => +b.data.date - +a.data.date || b.id.localeCompare(a.id));
  const lines = [
    `# ${SITE_NAME} changelog`,
    '',
    `> Every notable change to ${SITE_NAME}: decisions, documentation, and releases, newest first.`,
    '',
    `Source: ${new URL('/changelog/', SITE_URL).href}`,
    `RSS: ${new URL('/changelog/rss.xml', SITE_URL).href}`,
    `Project: ${SITE_NAME}`,
    '',
    ...entries.map(
      (entry) =>
        `- ${entry.data.date.toISOString().slice(0, 10)}: [${entry.data.title}](${new URL(`/changelog/${entry.id}.md`, SITE_URL).href}): ${entry.data.summary}`,
    ),
  ];
  return new Response(lines.join('\n') + '\n', { headers: { 'Content-Type': 'text/markdown; charset=utf-8' } });
};
