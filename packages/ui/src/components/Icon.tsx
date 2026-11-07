import type { SVGProps } from 'react';

// 24px line icons drawn on one grid: 1.75 stroke, round caps and joins, so they sit with Mona Sans.
const paths = {
  search: <><circle cx="11" cy="11" r="6.5" /><path d="m20 20-4.2-4.2" /></>,
  plus: <path d="M12 5v14M5 12h14" />,
  copy: <><rect x="8.5" y="8.5" width="11" height="11" rx="2.5" /><path d="M15.5 8.5V6.5a2 2 0 0 0-2-2h-7a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h2" /></>,
  eye: <><path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12Z" /><circle cx="12" cy="12" r="3" /></>,
  eyeOff: <><path d="M10.6 5.6A9.6 9.6 0 0 1 12 5.5c6 0 9.5 6.5 9.5 6.5a17 17 0 0 1-2.4 3.2M6.6 6.6C4 8.3 2.5 12 2.5 12S6 18.5 12 18.5c1.9 0 3.6-.6 5-1.5" /><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2M3 3l18 18" /></>,
  lock: <><rect x="4.5" y="10.5" width="15" height="10" rx="2.5" /><path d="M8 10.5V7.5a4 4 0 0 1 8 0v3" /></>,
  star: <path d="m12 3.8 2.5 5.1 5.6.8-4 4 1 5.6-5.1-2.7-5 2.7.9-5.6-4-4 5.6-.8Z" />,
  trash: <><path d="M4.5 7h15M10 11v5.5M14 11v5.5M6 7l.9 11.2A2 2 0 0 0 8.9 20h6.2a2 2 0 0 0 2-1.8L18 7" /><path d="M9 7V5.5A1.5 1.5 0 0 1 10.5 4h3A1.5 1.5 0 0 1 15 5.5V7" /></>,
  restore: <><path d="M4 12a8 8 0 1 0 2.3-5.6L4 8.7" /><path d="M4 4v4.7h4.7" /></>,
  settings: <><circle cx="12" cy="12" r="3" /><path d="M19.4 14.6a1.6 1.6 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.6 1.6 0 0 0-1.8-.3 1.6 1.6 0 0 0-1 1.5v.2a2 2 0 0 1-4 0v-.1a1.6 1.6 0 0 0-1-1.5 1.6 1.6 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.6 1.6 0 0 0 .3-1.8 1.6 1.6 0 0 0-1.5-1h-.2a2 2 0 0 1 0-4h.1a1.6 1.6 0 0 0 1.5-1 1.6 1.6 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.6 1.6 0 0 0 1.8.3h.1a1.6 1.6 0 0 0 1-1.5v-.2a2 2 0 0 1 4 0v.1a1.6 1.6 0 0 0 1 1.5 1.6 1.6 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.6 1.6 0 0 0-.3 1.8v.1a1.6 1.6 0 0 0 1.5 1h.2a2 2 0 0 1 0 4h-.1a1.6 1.6 0 0 0-1.5 1Z" /></>,
  shield: <><path d="M12 3.5 5 6v5.5c0 4.3 2.9 7.8 7 9 4.1-1.2 7-4.7 7-9V6Z" /><path d="m9 12 2 2 4-4" /></>,
  code: <path d="m8 8-4 4 4 4M16 8l4 4-4 4M13.5 5.5l-3 13" />,
  key: <><circle cx="8" cy="15" r="4" /><path d="m11 12 8.5-8.5M16.5 6.5l2.5 2.5M14 9l2 2" /></>,
  card: <><rect x="3" y="5.5" width="18" height="13" rx="2.5" /><path d="M3 10h18M7 15h3" /></>,
  identity: <><rect x="3" y="5" width="18" height="14" rx="2.5" /><circle cx="9" cy="11" r="2.2" /><path d="M5.8 16.2a3.4 3.4 0 0 1 6.4 0M14.5 10h3.5M14.5 13.5h3.5" /></>,
  document: <><path d="M6.5 3.5h8l4 4v11a2 2 0 0 1-2 2h-10a2 2 0 0 1-2-2v-13a2 2 0 0 1 2-2Z" /><path d="M14 3.5V8h4.5" /><circle cx="12" cy="14" r="2.75" /></>,
  paperclip: <path d="m19.5 11.5-7.4 7.4a4.6 4.6 0 0 1-6.5-6.5l7.6-7.6a3 3 0 0 1 4.3 4.3l-7.6 7.6a1.5 1.5 0 0 1-2.1-2.1l7-7" />,
  camera: <><path d="M3.5 9a2 2 0 0 1 2-2h2.3l1.6-2.5h5.2L16.2 7h2.3a2 2 0 0 1 2 2v8.5a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2Z" /><circle cx="12" cy="13" r="3.5" /></>,
  image: <><rect x="3.5" y="4.5" width="17" height="15" rx="2.5" /><circle cx="9" cy="9.5" r="1.6" /><path d="m4 17.5 5-5 4 4 2.5-2.5 4.5 4.5" /></>,
  note: <><path d="M6.5 3.5h8l4 4v11a2 2 0 0 1-2 2h-10a2 2 0 0 1-2-2v-13a2 2 0 0 1 2-2Z" /><path d="M14 3.5V8h4.5M8 12.5h8M8 16h5" /></>,
  login: <><circle cx="12" cy="12" r="8.5" /><path d="M3.5 12h17M12 3.5c2.3 2.3 3.4 5.2 3.4 8.5s-1.1 6.2-3.4 8.5c-2.3-2.3-3.4-5.2-3.4-8.5S9.7 5.8 12 3.5Z" /></>,
  password: <><rect x="3" y="7" width="18" height="10" rx="2.5" /><path d="M7.5 12h.01M12 12h.01M16.5 12h.01" strokeWidth="2.6" /></>,
  passkey: <><circle cx="9.5" cy="8" r="3.5" /><path d="M3.5 19.5a6 6 0 0 1 9.4-5" /><circle cx="17" cy="13.5" r="2.2" /><path d="M17 15.7v4.3l1.5-1.2M17 18h1.5" /></>,
  wand: <><path d="m5 19 10-10M13.5 7.5l3 3" /><path d="M17 3v3M15.5 4.5h3M20 9v2M19 10h2M10 3v2M9 4h2" /></>,
  chevronRight: <path d="m9.5 5.5 6.5 6.5-6.5 6.5" />,
  chevronLeft: <path d="m14.5 5.5-6.5 6.5 6.5 6.5" />,
  chevronDown: <path d="m5.5 9.5 6.5 6.5 6.5-6.5" />,
  close: <path d="M6 6l12 12M18 6 6 18" />,
  check: <path d="m5 12.5 4.5 4.5L19 7.5" />,
  alert: <><path d="M10.3 4.2 2.9 17.5A2 2 0 0 0 4.6 20.5h14.8a2 2 0 0 0 1.7-3L13.7 4.2a2 2 0 0 0-3.4 0Z" /><path d="M12 9.5v4M12 17h.01" /></>,
  info: <><circle cx="12" cy="12" r="8.5" /><path d="M12 11v5.5M12 7.8h.01" /></>,
  edit: <><path d="M4.5 19.5h4l10-10a2.8 2.8 0 0 0-4-4l-10 10Z" /><path d="m13.5 6.5 4 4" /></>,
  external: <><path d="M14 4.5h5.5V10M19.5 4.5 11 13" /><path d="M18 14v4a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4" /></>,
  refresh: <><path d="M19.5 12a7.5 7.5 0 0 1-13 5.1M4.5 12a7.5 7.5 0 0 1 13-5.1" /><path d="M17.5 3.5v3.4h-3.4M6.5 20.5v-3.4h3.4" /></>,
  download: <><path d="M12 4v11M7.5 10.5 12 15l4.5-4.5" /><path d="M4.5 16.5v2a2 2 0 0 0 2 2h11a2 2 0 0 0 2-2v-2" /></>,
  upload: <><path d="M12 15V4M7.5 8.5 12 4l4.5 4.5" /><path d="M4.5 16.5v2a2 2 0 0 0 2 2h11a2 2 0 0 0 2-2v-2" /></>,
  sun: <><circle cx="12" cy="12" r="3.8" /><path d="M12 2.8v1.9M12 19.3v1.9M4.7 4.7 6 6M18 18l1.3 1.3M2.8 12h1.9M19.3 12h1.9M4.7 19.3 6 18M18 6l1.3-1.3" /></>,
  moon: <path d="M19.5 14.5A7.5 7.5 0 0 1 9.5 4.5a7.5 7.5 0 1 0 10 10Z" />,
  monitor: <><rect x="3" y="4.5" width="18" height="12" rx="2" /><path d="M8.5 20h7M12 16.5V20" /></>,
  users: <><circle cx="9" cy="8.5" r="3.2" /><path d="M3 19a6 6 0 0 1 12 0" /><path d="M15.5 5.6a3.2 3.2 0 0 1 0 5.8M17.5 13.6A6 6 0 0 1 21 19" /></>,
  qrCode: <><rect x="4" y="4" width="6" height="6" rx="1.2" /><rect x="14" y="4" width="6" height="6" rx="1.2" /><rect x="4" y="14" width="6" height="6" rx="1.2" /><path d="M14 14h2.5v2.5M20 14v.01M14 20h.01M17.5 20H20v-2.5" /></>,
  grid: <><rect x="4" y="4" width="6.5" height="6.5" rx="1.6" /><rect x="13.5" y="4" width="6.5" height="6.5" rx="1.6" /><rect x="4" y="13.5" width="6.5" height="6.5" rx="1.6" /><rect x="13.5" y="13.5" width="6.5" height="6.5" rx="1.6" /></>,
  vault: <><rect x="3.5" y="4.5" width="17" height="15" rx="2.5" /><circle cx="12" cy="12" r="3.5" /><path d="M12 8.5V7M12 17v-1.5M15.5 12H17M7 12h1.5M6.5 19.5v1M17.5 19.5v1" /></>,
  more: <path d="M6 12h.01M12 12h.01M18 12h.01" strokeWidth="2.8" />,
  menu: <path d="M4 7h16M4 12h16M4 17h16" />,
  signOut: <><path d="M14 4.5h3.5a2 2 0 0 1 2 2v11a2 2 0 0 1-2 2H14" /><path d="M10 16.5 5.5 12 10 7.5M5.5 12H15" /></>,
  clock: <><circle cx="12" cy="12" r="8.5" /><path d="M12 7.5V12l3 2" /></>,
  mail: <><rect x="3" y="5.5" width="18" height="13" rx="2.5" /><path d="m4 7.5 8 5.5 8-5.5" /></>,
  phone: <><rect x="7" y="3" width="10" height="18" rx="2.5" /><path d="M11 17.5h2" /></>,
  server: <><rect x="4" y="4" width="16" height="7" rx="2" /><rect x="4" y="13" width="16" height="7" rx="2" /><path d="M8 7.5h.01M8 16.5h.01" strokeWidth="2.4" /></>,
  printer: <><path d="M7 9V4h10v5" /><rect x="3.5" y="9" width="17" height="7.5" rx="2" /><path d="M7 14h10v6H7Z" /></>,
  sparkle: <path d="M12 3.5c.6 3.9 2.6 5.9 6.5 6.5-3.9.6-5.9 2.6-6.5 6.5-.6-3.9-2.6-5.9-6.5-6.5 3.9-.6 5.9-2.6 6.5-6.5ZM18.5 15.5c.3 1.7 1.1 2.5 2.8 2.8-1.7.3-2.5 1.1-2.8 2.8-.3-1.7-1.1-2.5-2.8-2.8 1.7-.3 2.5-1.1 2.8-2.8Z" />,
  tag: <><path d="M3.5 12.3V4.5a1 1 0 0 1 1-1h7.8l8.2 8.2a1.4 1.4 0 0 1 0 2l-6.8 6.8a1.4 1.4 0 0 1-2 0Z" /><circle cx="8" cy="8" r="1.4" /></>,
  fingerprint: <><path d="M6.6 6.2A7.5 7.5 0 0 1 19.5 11.5v1" /><path d="M4.6 9.4a7.6 7.6 0 0 0-.1 1.6v1.5" /><path d="M8.5 19.8c.6-1.5 1-3.4 1-5.3v-2.8a2.5 2.5 0 0 1 5 0v2" /><path d="M12 11.7v2.8c0 2.6-.6 5.1-1.7 7" /><path d="M14.5 17.5c-.2 1.3-.6 2.6-1.1 3.7" /><path d="M7 12v2.5a12 12 0 0 1-1.2 5.2" /><path d="M17 14.5v.5c0 .8-.1 1.6-.2 2.3" /></>,
  faceId: <><path d="M3.5 8V6a2.5 2.5 0 0 1 2.5-2.5h2M16 3.5h2A2.5 2.5 0 0 1 20.5 6v2M20.5 16v2a2.5 2.5 0 0 1-2.5 2.5h-2M8 20.5H6A2.5 2.5 0 0 1 3.5 18v-2" /><path d="M8.5 9v1.5M15.5 9v1.5M12 9v4h-1M9 16s1.1 1.2 3 1.2 3-1.2 3-1.2" /></>,
  history: <><path d="M4 12a8 8 0 1 0 2.3-5.6L4 8.7" /><path d="M4 4v4.7h4.7M12 8v4.5l3 1.8" /></>,
  link: <><path d="M10 14a4 4 0 0 0 5.7 0l3.1-3.1a4 4 0 0 0-5.7-5.7l-1.2 1.2" /><path d="M14 10a4 4 0 0 0-5.7 0l-3.1 3.1a4 4 0 0 0 5.7 5.7l1.2-1.2" /></>,
  share: <><path d="M12 15V4M8 7.5 12 3.5l4 4" /><path d="M8.5 10.5H7a2 2 0 0 0-2 2V18a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-5.5a2 2 0 0 0-2-2h-1.5" /></>,
  lifebuoy: <><circle cx="12" cy="12" r="8.5" /><circle cx="12" cy="12" r="3.5" /><path d="m6 6 3.5 3.5M14.5 14.5 18 18M18 6l-3.5 3.5M9.5 14.5 6 18" /></>,
  move: <><path d="M4 12h12M12.5 8l4 4-4 4" /><path d="M19.5 5v14" /></>,
  userPlus: <><circle cx="10" cy="8.5" r="3.2" /><path d="M4 19a6 6 0 0 1 11.2-3" /><path d="M18.5 13.5v6M15.5 16.5h6" /></>,
  home: <><path d="M4 10.5 12 4l8 6.5V18a2 2 0 0 1-2 2h-3.5v-5.5h-5V20H6a2 2 0 0 1-2-2Z" /></>,
  keyboard: <><rect x="2.5" y="6" width="19" height="12" rx="2.5" /><path d="M6.5 10h.01M10 10h.01M13.5 10h.01M17 10h.01M6.5 13.5h.01M17 13.5h.01M9.5 14h5" /></>,
  sort: <path d="M7.5 4.5v15M4 16l3.5 3.5L11 16M16.5 19.5v-15M13 8l3.5-3.5L20 8" />,
  pin: <><path d="M8.5 3.5h7M10 3.5V9l-3.5 4h11L14 9V3.5" /><path d="M12 13v7.5" /></>,
  mapPin: <><path d="M12 20.5s6.5-5.4 6.5-10.5a6.5 6.5 0 0 0-13 0c0 5.1 6.5 10.5 6.5 10.5Z" /><circle cx="12" cy="10" r="2.5" /></>,
  trending: <><path d="m3.5 16.5 5.5-5.5 4 4 7-7" /><path d="M15 8h5v5" /></>,
  wifi: <><path d="M2.5 9a14 14 0 0 1 19 0M5.5 12.5a9.5 9.5 0 0 1 13 0M8.5 16a5 5 0 0 1 7 0" /><circle cx="12" cy="19.2" r="0.6" /></>,
} as const;

export type IconName = keyof typeof paths;

/** Icons that point somewhere, so they flip in right-to-left pages. The rest (checks, locks, clocks, the logo) never do. */
const MIRRORED: ReadonlySet<IconName> = new Set(['chevronRight', 'chevronLeft', 'signOut', 'move', 'external']);

export interface IconProps extends Omit<SVGProps<SVGSVGElement>, 'name'> {
  name: IconName;
  size?: number;
  /** Give a label only when the icon carries meaning on its own; otherwise it's hidden from assistive tech. */
  label?: string;
}

export function Icon({ name, size = 20, label, ...rest }: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      width={size}
      height={size}
      fill="none"
      stroke="currentColor"
      strokeWidth={1.75}
      strokeLinecap="round"
      strokeLinejoin="round"
      role={label ? 'img' : undefined}
      aria-label={label}
      aria-hidden={label ? undefined : true}
      focusable="false"
      data-mirror={MIRRORED.has(name) ? '' : undefined}
      {...rest}
    >
      {paths[name]}
    </svg>
  );
}
