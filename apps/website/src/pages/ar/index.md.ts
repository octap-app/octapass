// The Arabic landing page as Markdown, for AI agents. See ../index.md.ts.
import type { APIRoute } from 'astro';
import { getCollection } from 'astro:content';
import { landingMarkdown } from '../../lib/landing-markdown';

export const GET: APIRoute = async () => {
  const ids = new Set((await getCollection('docs')).map((entry) => entry.id));
  return new Response(landingMarkdown('ar', (id) => ids.has(id)), {
    headers: { 'Content-Type': 'text/markdown; charset=utf-8' },
  });
};
