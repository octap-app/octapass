import { Icon } from '@octapass/ui';
import type { ItemSummary, SiteEntry } from '@octapass/vault-client';
import { useEffect, useId, type ReactNode } from 'react';
import { t } from '../../i18n';
import { useOpenSites } from '../../lib/listArrangement';
import { ItemAvatar } from '../../lib/siteIcons';
import styles from './SiteGroup.module.css';

/**
 * Two or more logins for one website as a single row. It opens in place, with the logins indented
 * under it, and stays open while the vault is unlocked. It opens by itself when one of its logins is
 * the item showing.
 */
export function SiteGroup({ site, activeId, listClassName, renderItem }: { site: SiteEntry; activeId: string | undefined; listClassName: string | undefined; renderItem: (item: ItemSummary) => ReactNode }) {
  const id = useId();
  const { isOpen, setOpen } = useOpenSites();
  const open = isOpen(site.host);
  const holdsActive = Boolean(activeId && site.items.some((item) => item.id === activeId));

  useEffect(() => {
    if (holdsActive) setOpen(site.host, true);
  }, [holdsActive, setOpen, site.host]);

  return (
    <li className={styles.group}>
      <button
        type="button"
        className={[styles.row, !open && holdsActive && styles.rowOn].filter(Boolean).join(' ')}
        aria-expanded={open}
        aria-controls={open ? id : undefined}
        data-site={site.host}
        onClick={() => setOpen(site.host, !open)}
      >
        <ItemAvatar name={site.host} urls={[site.host]} />
        <span className={styles.text}>
          <span className={styles.title}>
            <bdi>{site.host}</bdi>
          </span>
          <span className={styles.sub}>{t('list.siteAccounts', { count: site.items.length })}</span>
        </span>
        <Icon name="chevronDown" size={18} className={styles.chevron} />
      </button>
      {open && (
        <ul id={id} className={[listClassName, styles.logins].filter(Boolean).join(' ')} aria-label={site.host}>
          {site.items.map(renderItem)}
        </ul>
      )}
    </li>
  );
}
