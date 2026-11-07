import rss from '@astrojs/rss';
import type { APIRoute } from 'astro';
import { getCollection } from 'astro:content';
import { SITE_NAME, SITE_URL } from '../../site.config';

export const GET: APIRoute = async () => {
  const entries = (await getCollection('changelog')).sort((a, b) => +b.data.date - +a.data.date);
  return rss({
    title: `${SITE_NAME} changelog`,
    description: `Notable changes to ${SITE_NAME}: decisions, docs, releases.`,
    site: SITE_URL,
    items: entries.map((entry) => ({
      title: entry.data.title,
      description: entry.data.summary,
      pubDate: entry.data.date,
      link: `/changelog/${entry.id}/`,
      categories: entry.data.tags,
    })),
  });
};
