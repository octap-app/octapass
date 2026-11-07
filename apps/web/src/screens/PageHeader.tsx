import { IconButton } from '@octapass/ui';
import type { ReactNode } from 'react';
import { useOutletContext } from 'react-router';
import { t } from '../i18n';
import type { LayoutContext } from './vault/VaultLayout';
import styles from './PageHeader.module.css';

/** The heading for full-width pages (Generator, Health, Settings), with the drawer button on small screens. */
export function PageHeader({ title, subtitle, actions, narrow }: { title: string; subtitle?: ReactNode; actions?: ReactNode; narrow?: boolean }) {
  const { openDrawer } = useOutletContext<LayoutContext>();
  return (
    <header className={[styles.header, narrow && styles.narrow].filter(Boolean).join(' ')}>
      <div className={styles.row}>
        <IconButton icon="menu" label={t('nav.openMenu')} className={styles.menu} onClick={openDrawer} />
        <h1 className={styles.title}>{title}</h1>
        {actions}
      </div>
      {subtitle && <p className={styles.subtitle}>{subtitle}</p>}
    </header>
  );
}
