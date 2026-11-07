// Per-page social images: /og/en/docs/security/encryption.png, /og/ar/docs/….png, /og/en/changelog/<slug>.png.
import type { APIRoute, GetStaticPaths } from 'astro';
import { getCollection } from 'astro:content';
import { stringsFor, type Locale } from '../../../i18n/landing';
import { ogImage } from '../../../lib/og-image';

// Section names for the small line above the title. Folder names are the keys.
const sections: Record<Locale, Record<string, string>> = {
  en: {
    'getting-started': 'Getting started',
    features: 'Features',
    'import-export': 'Import and export',
    platforms: 'Platforms',
    security: 'Security',
    'self-hosting': 'Self-hosting',
    developers: 'Developers',
    contributing: 'Contributing',
    reference: 'Reference',
  },
  ar: {
    'getting-started': 'البدء',
    features: 'الميزات',
    'import-export': 'الاستيراد والتصدير',
    platforms: 'المنصات',
    security: 'الأمان',
    'self-hosting': 'الاستضافة الذاتية',
    developers: 'المطورون',
    contributing: 'المساهمة',
    reference: 'المرجع',
  },
};

interface Props {
  title: string;
  section: string;
}

export const getStaticPaths = (async () => {
  const docs = await getCollection('docs');
  const changelog = await getCollection('changelog');
  return [
    ...(['en', 'ar'] as const).map((locale) => ({
      params: { locale, slug: 'home' },
      props: { title: stringsFor(locale).hero.title, section: '' },
    })),
    ...docs.map((entry) => {
      const locale: Locale = entry.id.startsWith('ar/') ? 'ar' : 'en';
      const slug = entry.id.replace(/^ar\//, '');
      return { params: { locale, slug }, props: { title: entry.data.title, section: sections[locale][slug.split('/')[1]] ?? '' } };
    }),
    { params: { locale: 'en', slug: 'changelog' }, props: { title: 'Changelog', section: '' } },
    ...changelog.map((entry) => ({
      params: { locale: 'en', slug: `changelog/${entry.id}` },
      props: { title: entry.data.title, section: 'Changelog' },
    })),
  ];
}) satisfies GetStaticPaths;

export const GET: APIRoute<Props, { locale: Locale; slug: string }> = async ({ props, params }) =>
  new Response(new Uint8Array(await ogImage({ ...props, locale: params.locale })), { headers: { 'Content-Type': 'image/png' } });
