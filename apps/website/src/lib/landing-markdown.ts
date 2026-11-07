// The landing page as Markdown (/index.md, /ar/index.md), for AI agents and tools.
// Built from the same strings as Landing.astro (src/i18n/landing), so the two can't drift apart.
import { localePath, stringsFor, type Locale } from '../i18n/landing';
import { isPlatformId, platformLink, REPO_URL, repoFile, repoTree, SITE_NAME, SITE_URL, SOURCE_PATHS, VAULT_URL } from '../site.config';

/** Inline HTML in the strings (<b>, <a href>) → Markdown. */
const md = (html: string) =>
  html
    .replace(/<b>(.*?)<\/b>/g, '**$1**')
    .replace(/<a href="([^"]+)">(.*?)<\/a>/g, '[$2]($1)')
    .replace(/<[^>]+>/g, '');

/**
 * @param hasDoc whether a docs entry id (`ar/docs/security/overview`) exists; an untranslated page has no
 *   Arabic Markdown twin, so links fall back to the English one.
 */
export function landingMarkdown(locale: Locale, hasDoc: (id: string) => boolean): string {
  const t = stringsFor(locale);
  const abs = (path: string) => new URL(localePath(locale, path), SITE_URL).href;
  // Links to docs pages point at their Markdown twins.
  const doc = (path: string) => {
    const id = localePath(locale, `/docs/${path}`).slice(1);
    return new URL(`/${hasDoc(id) ? id : `docs/${path}`}.md`, SITE_URL).href;
  };
  const named = (text: string, name: string) => text.replace('{name}', name);

  const bento = t.bento;
  const features = [
    [bento.passkeysTitle, bento.passkeysBody],
    [bento.otpTitle, bento.otpBody],
    [bento.fillTitle, bento.fillBody],
    [bento.breachTitle, `${bento.breachBody} [${bento.breachLink}](${doc('security/breach-checks')})`],
    [bento.aliasTitle, bento.aliasBody],
    [bento.recoveryTitle, bento.recoveryBody],
    [bento.cardsTitle, bento.cardsBody],
    [bento.importTitle, bento.importBody],
  ];

  const platforms = t.platforms.items.map((p) => {
    if (!isPlatformId(p.id)) throw new Error(`Unknown platform id "${p.id}" in src/i18n/landing/${locale}.json`);
    const link = platformLink(p.id);
    const availability =
      link?.kind === 'open' ? `[${t.platforms.openVault}](${link.href})`
      : link?.kind === 'store' ? `[${named(t.platforms.getLabel, p.name)}](${link.href})`
      : t.platforms.soon;
    return `- **${p.name}**: ${p.detail} ${availability}. [${t.platforms.source}](${repoTree(SOURCE_PATHS[p.id])})`;
  });

  const projectLinks = [
    [t.open.repo, REPO_URL],
    [t.open.licence, repoFile('LICENSE')],
    [t.open.contributing, repoFile('CONTRIBUTING.md')],
    [t.open.security, repoFile('SECURITY.md')],
    [t.open.issues, `${REPO_URL}/issues`],
    [t.open.selfHost, doc('self-hosting/overview')],
  ];

  const sections = [
    `# ${SITE_NAME}: ${t.hero.title}`,
    `> ${t.meta.description}`,
    [
      `Source: ${abs('/')}`,
      `Web vault: ${VAULT_URL}`,
      `Code: ${REPO_URL} (MIT)`,
      `Docs: ${new URL(`/${localePath(locale, '/docs').slice(1)}.md`, SITE_URL).href}`,
      `LLM index: ${new URL('/llms.txt', SITE_URL).href}`,
    ].join('\n'),
    `${t.hero.sub}\n\n${t.hero.status} [${t.hero.primary}](${VAULT_URL})`,
    `## ${t.statement.titleLine1} ${t.statement.titleLine2}\n\n${t.statement.lead}`,
    `## ${bento.titleLine1} ${bento.titleLine2}\n\n${features.map(([title, body]) => `- **${title}**: ${body}`).join('\n')}`,
    [
      `## ${t.free.titleLine1} ${t.free.titleLine2}`,
      t.free.features.map((f) => `- ${f}`).join('\n'),
      t.free.note,
      `### ${t.free.howTitle}`,
      [t.free.howTiny, t.free.howNoAds, t.free.howFunded].map((s) => `- ${md(s)}`).join('\n'),
    ].join('\n\n'),
    [
      `## ${t.sealed.title}`,
      t.sealed.steps.map((s, i) => `${i + 1}. **${s.title}**: ${s.body}`).join('\n'),
      `### ${t.sealed.seesTitle}\n\n${t.sealed.sees.map((s) => `- ${s}`).join('\n')}`,
      `### ${t.sealed.neverTitle}\n\n${t.sealed.never.map((s) => `- ${s}`).join('\n')}`,
      `[${t.sealed.more}](${doc('security/what-the-server-sees')})`,
    ].join('\n\n'),
    [
      `## ${t.platforms.title}`,
      t.platforms.lede,
      platforms.join('\n'),
      `[${t.platforms.more}](${doc('platforms/support-matrix')})`,
    ].join('\n\n'),
    [
      `## ${t.open.titleLine1} ${t.open.titleLine2}`,
      [t.open.code, t.open.server, t.open.noAds].map((s) => `- ${md(s)}`).join('\n'),
      `[${t.open.connect}](${doc('self-hosting/connect-apps')})`,
      `### ${t.open.linksLabel}\n\n${projectLinks.map(([label, href]) => `- [${label}](${href})`).join('\n')}`,
    ].join('\n\n'),
    [
      `## ${t.roadmap.title}`,
      t.roadmap.phases.map((p) => `- **${p.title}**: ${p.state}`).join('\n'),
      `[${t.roadmap.more}](${doc('reference/roadmap')})`,
    ].join('\n\n'),
    `## ${t.faq.title}\n\n${t.faq.items.map((f) => `### ${f.q}\n\n${md(f.a)}`).join('\n\n')}`,
    md(t.site.footer),
  ];
  return sections.join('\n\n') + '\n';
}
