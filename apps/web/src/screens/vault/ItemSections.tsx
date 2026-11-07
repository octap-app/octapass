import { arrangeItems, type ItemSummary, type ListGrouping, type ListSection, type Vault } from '@octapass/vault-client';
import { useId, useMemo, type KeyboardEvent, type ReactNode, type Ref } from 'react';
import { useMatch } from 'react-router';
import { formatNumber, getLocale, t, type MessageKey } from '../../i18n';
import type { ListArrangement } from '../../lib/listArrangement';
import { ITEM_TYPES } from '../../lib/scope';
import { SiteGroup } from './SiteGroup';
import styles from './ItemSections.module.css';

/** The Wi-Fi list's first section: the networks the device is on or sees. */
export const IN_RANGE_SECTION = 'inRange';

export function sectionLabel(grouping: ListGrouping, key: string, vaults: Vault[] | undefined): string {
  if (key === IN_RANGE_SECTION) return t('list.inRange');
  switch (grouping) {
    case 'type':
      if (ITEM_TYPES.includes(key as never)) return t(`categories.${key}` as MessageKey);
      return key === 'maskedEmailProvider' ? t('types.maskedEmailProvider') : t('list.otherType');
    case 'vault':
      return vaults?.find((v) => v.id === key)?.name ?? t('scopes.vault');
    case 'project':
      return key || t('env.noProject');
    default:
      return key;
  }
}

/** The items in the chosen order, split into sections for the chosen grouping, with logins for one website combined if asked. */
export function useSections(items: ItemSummary[] | undefined, { sort, grouping }: ListArrangement, vaults: Vault[] | undefined, combineSites = false): ListSection[] {
  const vaultOrder = useMemo(() => vaults?.map((v) => v.id), [vaults]);
  return useMemo(
    () => (items ? arrangeItems(items, { sort, grouping, combineSites, locale: getLocale(), ...(vaultOrder ? { vaultOrder } : {}) }) : []),
    [items, sort, grouping, combineSites, vaultOrder],
  );
}

/**
 * Sections with a header that stays at the top of the scrolling list while its rows pass under it.
 * Without grouping, the rows are one plain list.
 */
export function ItemSections({
  sections,
  grouping,
  vaults,
  className,
  listClassName,
  containerRef,
  onKeyDown,
  renderItem,
}: {
  sections: ListSection[];
  grouping: ListGrouping;
  vaults: Vault[] | undefined;
  className?: string | undefined;
  listClassName: string | undefined;
  containerRef?: Ref<HTMLDivElement>;
  onKeyDown?: (event: KeyboardEvent) => void;
  renderItem: (item: ItemSummary) => ReactNode;
}) {
  const id = useId();
  const activeId = useMatch('/items/:scope/:itemId/*')?.params.itemId;
  const rows = (section: ListSection) =>
    section.entries
      ? section.entries.map((entry) =>
          entry.kind === 'item' ? renderItem(entry.item) : <SiteGroup key={`site:${entry.host}`} site={entry} activeId={activeId} listClassName={listClassName} renderItem={renderItem} />,
        )
      : section.items.map(renderItem);
  return (
    <div ref={containerRef} onKeyDown={onKeyDown} className={[styles.sections, className].filter(Boolean).join(' ')}>
      {grouping === 'none'
        ? sections.map((section) => (
            <ul key={section.key} className={listClassName}>
              {rows(section)}
            </ul>
          ))
        : sections.map((section, index) => (
            <section key={section.key} aria-labelledby={`${id}-${index}`} data-section={section.key}>
              <h2 id={`${id}-${index}`} className={styles.header}>
                <bdi className={styles.name}>{sectionLabel(grouping, section.key, vaults)}</bdi>{' '}
                <span className={styles.count} aria-hidden="true">
                  {formatNumber(section.items.length)}
                </span>
                <span className="visually-hidden">{t('list.sectionCount', { count: section.items.length })}</span>
              </h2>
              <ul className={listClassName}>{rows(section)}</ul>
            </section>
          ))}
    </div>
  );
}
