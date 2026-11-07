import { Logo } from '@octapass/ui';
import type { ReactNode } from 'react';
import styles from './AuthLayout.module.css';

export interface AuthLayoutProps {
  title: ReactNode;
  subtitle?: ReactNode;
  children?: ReactNode;
  /** Small print under the card. */
  footer?: ReactNode;
  wide?: boolean;
  /** Above the title, e.g. wizard progress. */
  top?: ReactNode;
}

/** The centred card used by every signed-out screen, on the brand glow from the website hero. */
export function AuthLayout({ title, subtitle, children, footer, wide, top }: AuthLayoutProps) {
  return (
    <div className={styles.page}>
      <div className={styles.glow} aria-hidden="true" />
      <main className={[styles.card, wide && styles.wide].filter(Boolean).join(' ')}>
        {top}
        <Logo variant="tile" size={56} className={styles.logo} />
        <h1 className={styles.title} tabIndex={-1}>{title}</h1>
        {subtitle && <p className={styles.subtitle}>{subtitle}</p>}
        {children && <div className={styles.body}>{children}</div>}
      </main>
      {footer && <div className={styles.footer}>{footer}</div>}
    </div>
  );
}
