import { Icon, IconButton } from '@octapass/ui';
import { LIST_SORTS, type ListGrouping } from '@octapass/vault-client';
import { useEffect, useId, useRef, useState, type KeyboardEvent } from 'react';
import { t, type MessageKey } from '../i18n';
import type { ListArrangement } from '../lib/listArrangement';
import styles from './SortMenu.module.css';

interface Option {
  key: string;
  label: string;
  checked: boolean;
  onSelect: () => void;
}

/**
 * The list's "Sort and group" menu: two sets of radio items in one menu, following the WAI-ARIA menu
 * button pattern, and the "Combine accounts for the same website" checkbox when the list has logins.
 * A popover under the button, a sheet from the bottom on phones.
 */
export function SortMenu({
  value,
  groupings,
  onChange,
  combineSites,
}: {
  value: ListArrangement;
  groupings: readonly ListGrouping[];
  onChange: (next: ListArrangement) => void;
  combineSites?: { on: boolean; onChange: (on: boolean) => void } | undefined;
}) {
  const [open, setOpen] = useState(false);
  const id = useId();
  const root = useRef<HTMLDivElement>(null);
  const menu = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    menu.current?.querySelector<HTMLElement>('[aria-checked="true"]')?.focus();
    const onPointer = (event: PointerEvent) => {
      if (!root.current?.contains(event.target as Node)) setOpen(false);
    };
    document.addEventListener('pointerdown', onPointer);
    return () => document.removeEventListener('pointerdown', onPointer);
  }, [open]);

  function close() {
    setOpen(false);
    root.current?.querySelector<HTMLElement>('[aria-haspopup]')?.focus();
  }

  function choose(next: ListArrangement) {
    onChange(next);
    close();
  }

  function onKeyDown(event: KeyboardEvent) {
    const entries = Array.from(menu.current?.querySelectorAll<HTMLElement>('[role="menuitemradio"], [role="menuitemcheckbox"]') ?? []);
    const index = entries.indexOf(document.activeElement as HTMLElement);
    const move = (to: number) => entries[(to + entries.length) % entries.length]?.focus();
    if (event.key === 'ArrowDown') move(index + 1);
    else if (event.key === 'ArrowUp') move(index - 1);
    else if (event.key === 'Home') move(0);
    else if (event.key === 'End') move(entries.length - 1);
    else if (event.key === 'Escape' || event.key === 'Tab') close();
    else return;
    event.preventDefault();
  }

  const sorts = LIST_SORTS.map((sort) => ({ key: sort, label: t(`list.sorts.${sort}` as MessageKey), checked: value.sort === sort, onSelect: () => choose({ ...value, sort }) }));
  const groups = groupings.map((grouping) => ({ key: grouping, label: t(`list.groupings.${grouping}` as MessageKey), checked: value.grouping === grouping, onSelect: () => choose({ ...value, grouping }) }));

  return (
    <div className={styles.root} ref={root}>
      <IconButton icon="sort" label={t('list.arrange')} aria-haspopup="menu" aria-expanded={open} aria-controls={id} onClick={() => setOpen((o) => !o)} />
      {open && (
        <>
          <div className={styles.backdrop} aria-hidden="true" onClick={close} />
          <div id={id} ref={menu} role="menu" aria-label={t('list.arrange')} className={styles.menu} onKeyDown={onKeyDown}>
            <Group label={t('list.sortBy')} options={sorts} />
            {groups.length > 1 && (
              <>
                <div role="separator" className={styles.separator} />
                <Group label={t('list.groupBy')} options={groups} />
              </>
            )}
            {combineSites && (
              <>
                <div role="separator" className={styles.separator} />
                <button
                  type="button"
                  role="menuitemcheckbox"
                  aria-checked={combineSites.on}
                  tabIndex={-1}
                  className={styles.item}
                  onClick={() => {
                    combineSites.onChange(!combineSites.on);
                    close();
                  }}
                >
                  <Icon name="check" size={16} className={styles.check} />
                  {t('list.combineSites')}
                </button>
              </>
            )}
          </div>
        </>
      )}
    </div>
  );
}

function Group({ label, options }: { label: string; options: Option[] }) {
  const id = useId();
  return (
    <div role="group" aria-labelledby={id}>
      <div id={id} className={styles.label}>
        {label}
      </div>
      {options.map((option) => (
        <button key={option.key} type="button" role="menuitemradio" aria-checked={option.checked} tabIndex={-1} className={styles.item} onClick={option.onSelect}>
          <Icon name="check" size={16} className={styles.check} />
          {option.label}
        </button>
      ))}
    </div>
  );
}
