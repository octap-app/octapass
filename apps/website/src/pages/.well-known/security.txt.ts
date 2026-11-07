// RFC 9116 security.txt. Built at each build, so Expires is always a year ahead of the deploy.
// Contacts follow SECURITY.md: a private GitHub advisory first, then email.
import type { APIRoute } from 'astro';
import { REPO_URL, repoFile, SITE_URL } from '../../site.config';

export const GET: APIRoute = () => {
  const expires = new Date();
  expires.setUTCFullYear(expires.getUTCFullYear() + 1);
  const body = [
    `Contact: ${REPO_URL}/security/advisories/new`,
    `Expires: ${expires.toISOString().replace(/\.\d{3}Z$/, 'Z')}`,
    `Policy: ${repoFile('SECURITY.md')}`,
    `Canonical: ${new URL('/.well-known/security.txt', SITE_URL).href}`,
    'Preferred-Languages: en, ar',
    '',
  ].join('\n');
  return new Response(body, { headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
};
