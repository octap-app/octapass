/**
 * The install scripts name the repository their releases come from and the site that serves them.
 * `repoUrl` is `https://github.com/<owner>/<repo>`; anything else is refused, so a misconfigured
 * build can't serve a script that downloads from somewhere unexpected.
 */
export function installScript(source: string, repoUrl: string, siteUrl: string): string {
  const match = /^https:\/\/github\.com\/([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+?)(?:\.git)?\/?$/.exec(repoUrl);
  if (!match) throw new Error(`The install scripts need a GitHub repository URL, not ${repoUrl}`);
  const site = siteUrl.replace(/\/+$/, '');
  return source.replaceAll('__OCTAPASS_REPO__', match[1]!).replaceAll('__OCTAPASS_SITE__', site);
}
