// Serves the CLI agent skill from the repo-root skills/ folder, with the configured site URL filled in.
import type { APIRoute } from 'astro';
import skill from '../../../../../../skills/octapass-cli/SKILL.md?raw';
import { SITE_URL } from '../../../site.config';

export const GET: APIRoute = () =>
  new Response(skill.replaceAll('https://octap.app', SITE_URL), {
    headers: { 'Content-Type': 'text/markdown; charset=utf-8' },
  });
