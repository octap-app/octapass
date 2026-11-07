import type { APIRoute } from 'astro';
import { SITE_URL } from '../site.config';

// AI crawlers are welcome: being cited accurately by assistants matters for an open-source project.
const aiCrawlers = [
  'GPTBot', 'OAI-SearchBot', 'ChatGPT-User', 'ClaudeBot', 'Claude-SearchBot', 'Claude-User',
  'PerplexityBot', 'Google-Extended', 'Applebot-Extended', 'CCBot', 'Meta-ExternalAgent', 'Amazonbot',
];

export const GET: APIRoute = () => {
  const body = [
    'User-agent: *',
    'Allow: /',
    '',
    ...aiCrawlers.flatMap((bot) => [`User-agent: ${bot}`, 'Allow: /', '']),
    `Sitemap: ${new URL('/sitemap-index.xml', SITE_URL).href}`,
    '',
    '# LLM-readable docs: /llms.txt, /llms-full.txt, /llms-small.txt',
    '# Every docs page, the home page and each changelog entry also has a Markdown copy at its path + .md, e.g. /index.md',
    '',
  ].join('\n');
  return new Response(body, { headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
};
