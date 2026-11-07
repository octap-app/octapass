// Draws one 1200×630 social image at build time: brand mark, section name, page title. Text goes
// through sharp's Pango renderer, which shapes Arabic properly and needs no browser or font service.
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import sharp from 'sharp';

// Astro builds from apps/website, and this module moves when it's bundled, so paths start there.
const fromSite = (path: string) => resolve(process.cwd(), path);

// Pango can't read WOFF2, and silently falls back to a system font if handed one. So Mona Sans is the
// TTF in the Android app's resources (`tools/native-fonts` keeps it the web's version), and Arabic is
// @fontsource's static WOFF.
const LATIN = fromSite('../android/resources/src/main/res/font/mona_sans.ttf');
const ARABIC = fromSite('node_modules/@fontsource/noto-sans-arabic/files/noto-sans-arabic-arabic-700-normal.woff');
const LOGO = readFileSync(fromSite('src/assets/logo-tile.svg'));

const WIDTH = 1200;
const HEIGHT = 630;
const MARGIN = 80;

const escape = (text: string) => text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

const background = (rtl: boolean) => `<svg xmlns="http://www.w3.org/2000/svg" width="${WIDTH}" height="${HEIGHT}">
  <defs>
    <linearGradient id="g" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0" stop-color="#2456F0" /><stop offset="0.5" stop-color="#1A86C8" /><stop offset="1" stop-color="#10B77F" />
    </linearGradient>
    <radialGradient id="glow" cx="${rtl ? '12%' : '88%'}" cy="8%" r="75%">
      <stop offset="0" stop-color="#2456F0" stop-opacity="0.34" /><stop offset="1" stop-color="#2456F0" stop-opacity="0" />
    </radialGradient>
  </defs>
  <rect width="${WIDTH}" height="${HEIGHT}" fill="#000000" />
  <rect width="${WIDTH}" height="${HEIGHT}" fill="url(#glow)" />
  <rect y="${HEIGHT - 10}" width="${WIDTH}" height="10" fill="url(#g)" />
</svg>`;

async function text(content: string, opts: { size: number; color: string; weight?: string; rtl: boolean; width: number }) {
  const markup = `<span foreground="${opts.color}" size="${opts.size * 1024}" weight="${opts.weight ?? 'normal'}">${escape(content)}</span>`;
  const options = {
    text: markup,
    fontfile: opts.rtl ? ARABIC : LATIN,
    font: opts.rtl ? 'Noto Sans Arabic' : 'Mona Sans',
    width: opts.width,
    rgba: true,
    dpi: 72,
    wrap: 'word',
    align: opts.rtl ? 'right' : 'left',
    spacing: Math.round(opts.size * 0.22),
  } as const;
  const image = sharp({ text: options });
  const { width = 0, height = 0 } = await image.metadata();
  return { buffer: await image.png().toBuffer(), width, height };
}

/** Longer titles get smaller type, so every title fits in the same space. */
const titleSize = (title: string, rtl: boolean) => {
  const length = title.length * (rtl ? 0.9 : 1);
  return length <= 28 ? 84 : length <= 52 ? 68 : length <= 84 ? 56 : 46;
};

export async function ogImage({ title, section, locale }: { title: string; section: string; locale: 'en' | 'ar' }) {
  const rtl = locale === 'ar';
  const inner = WIDTH - MARGIN * 2;
  const place = (width: number) => (rtl ? WIDTH - MARGIN - width : MARGIN);
  const mark = await sharp(LOGO, { density: 300 }).resize(72, 72).png().toBuffer();
  // A Latin word in an Arabic title (Octa Pass, Wi-Fi) falls back to Mona Sans once it's registered.
  await text('Octa Pass', { size: 12, color: '#ffffff', rtl: false, width: 200 });
  const name = await text('Octa Pass', { size: 34, color: '#F5F6F8', weight: 'bold', rtl: false, width: 420 });
  const heading = await text(title, { size: titleSize(title, rtl), color: '#FFFFFF', weight: 'bold', rtl, width: inner });
  const label = section ? await text(section, { size: 30, color: '#9BA3B4', rtl, width: inner }) : undefined;

  const headingTop = Math.max(190, HEIGHT - 90 - heading.height - (label ? label.height + 18 : 0));
  const layers = [
    { input: mark, top: MARGIN - 8, left: rtl ? WIDTH - MARGIN - 72 : MARGIN },
    { input: name.buffer, top: MARGIN + 28 - Math.round(name.height / 2), left: rtl ? WIDTH - MARGIN - 72 - 22 - name.width : MARGIN + 72 + 22 },
    ...(label ? [{ input: label.buffer, top: headingTop - label.height - 18, left: place(label.width) }] : []),
    { input: heading.buffer, top: headingTop, left: place(heading.width) },
  ];
  return sharp(Buffer.from(background(rtl))).composite(layers).png({ palette: true, quality: 90 }).toBuffer();
}
