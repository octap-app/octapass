import type { APIRoute } from 'astro';
import installPs1 from '../install/install.ps1?raw';
import { REPO_URL, SITE_URL } from '../site.config';
import { installScript } from '../install/render';

// `irm <site>/install.ps1 | iex`: the CLI for Windows (docs/platforms/cli.md#install).
export const GET: APIRoute = () =>
  new Response(installScript(installPs1, REPO_URL, SITE_URL), {
    headers: { 'Content-Type': 'text/plain; charset=utf-8' },
  });
