// The skill's references/ci.md, beside SKILL.md so its relative links work on the website.
import type { APIRoute } from 'astro';
import page from '../../../../../../../skills/octapass-cli/references/ci.md?raw';
import { SITE_URL } from '../../../../site.config';

export const GET: APIRoute = () =>
  new Response(page.replaceAll('https://octap.app', SITE_URL), {
    headers: { 'Content-Type': 'text/markdown; charset=utf-8' },
  });
