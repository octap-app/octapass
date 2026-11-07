import type { APIRoute } from 'astro';
import script from '../../../../../../../skills/octapass-docs/scripts/search_docs.py?raw';
import { SITE_URL } from '../../../../site.config';

export const GET: APIRoute = () =>
  new Response(script.replaceAll('https://octap.app', SITE_URL), {
    headers: { 'Content-Type': 'text/x-python; charset=utf-8' },
  });
