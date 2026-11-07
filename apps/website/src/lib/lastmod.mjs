// When each source file last changed, for the sitemap's <lastmod> and the JSON-LD dateModified.
// Read from git once per build: the date of the last commit that touched the file.
// Docker builds have no .git, so `deploy/octap.app/deploy.sh` writes the same `git log` output to
// apps/website/.git-dates.txt first (see `GIT_LOG_ARGS`). With neither, callers fall back to the build date.
import { execFileSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';

/** The `git log` that produces the dates, run from the repo root. deploy.sh runs the same command. */
export const GIT_LOG_ARGS = ['-c', 'core.quotePath=false', 'log', '--format=@@%cI', '--name-only', '--', 'docs', 'changelog', 'apps/website/src'];

export const BUILD_DATE = new Date().toISOString();

/** The repo root: the nearest folder above the working directory with pnpm-workspace.yaml. */
export function repoRoot(from = process.cwd()) {
  let dir = resolve(from);
  while (!existsSync(join(dir, 'pnpm-workspace.yaml'))) {
    const up = dirname(dir);
    if (up === dir) return resolve(from, '../..');
    dir = up;
  }
  return dir;
}

/** `git log --format=@@%cI --name-only` output → Map of repo-relative path → ISO date of its newest commit. */
export function parseGitLog(text) {
  const dates = new Map();
  let date;
  for (const line of text.split('\n')) {
    if (line.startsWith('@@')) date = line.slice(2).trim();
    else if (line.trim() && date && !dates.has(line.trim())) dates.set(line.trim(), date);
  }
  return dates;
}

let cache;
/** Repo-relative path → ISO date of the last commit touching it. Empty when there's no git and no snapshot. */
export function gitDates(root = repoRoot()) {
  if (cache) return cache;
  let text = '';
  try {
    text = execFileSync('git', GIT_LOG_ARGS, { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 64 * 1024 * 1024 });
  } catch {
    const snapshot = join(root, 'apps/website/.git-dates.txt');
    if (existsSync(snapshot)) text = readFileSync(snapshot, 'utf8');
  }
  cache = parseGitLog(text);
  return cache;
}

/** ISO date of the last commit touching `file` (absolute or repo-relative), or undefined if unknown. */
export function gitDate(file, root = repoRoot()) {
  const rel = relative(root, resolve(root, file)).replace(/\\/g, '/');
  return gitDates(root).get(rel);
}

/** A content entry's `filePath` (relative to the Astro root, the working directory of a build) → its git date. */
export const entryDate = (filePath) => (filePath ? gitDate(resolve(process.cwd(), filePath)) : undefined);

/** The newest of several ISO dates, ignoring missing ones. */
export const newest = (...dates) => dates.filter(Boolean).sort((a, b) => Date.parse(a) - Date.parse(b)).at(-1);

/**
 * Each docs URL path (`/docs/security/encryption/`, `/ar/docs/…`) → the repo-relative file it's built from.
 * An Arabic URL with no Arabic file is Starlight's fallback page, built from the English file.
 */
export function docsSourceMap(root = repoRoot()) {
  const docsDir = join(root, 'docs');
  const walk = (dir) =>
    readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) return walk(path);
      return /\.mdx?$/.test(entry.name) && !entry.name.startsWith('_') ? [path] : [];
    });
  const map = new Map();
  for (const file of walk(docsDir)) {
    const rel = relative(docsDir, file).replace(/\\/g, '/');
    const slug = rel.replace(/\.mdx?$/, '').replace(/(^|\/)index$/, '');
    const [, locale, rest = ''] = slug.match(/^(ar)(?:\/(.*))?$/) ?? [];
    const path = locale ? `/ar/docs/${rest ? `${rest}/` : ''}` : `/docs/${slug ? `${slug}/` : ''}`;
    map.set(path, relative(root, file).replace(/\\/g, '/'));
  }
  for (const [path, file] of [...map]) {
    if (!path.startsWith('/ar/') && !map.has(`/ar${path}`)) map.set(`/ar${path}`, file);
  }
  return map;
}
