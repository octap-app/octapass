import type { APIRoute } from 'astro';
import installSh from '../install/install.sh?raw';
import { REPO_URL, SITE_URL } from '../site.config';
import { installScript } from '../install/render';

// `curl -fsSL <site>/install.sh | sh`: the CLI for macOS and Linux (docs/platforms/cli.md#install).
export const GET: APIRoute = () =>
  new Response(installScript(installSh, REPO_URL, SITE_URL), {
    headers: { 'Content-Type': 'text/x-shellscript; charset=utf-8' },
  });
