import { Icon, type IconName } from '@octapass/ui';
import { useEffect, useId, useRef, useState, type KeyboardEvent, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import { useMediaQuery } from '../lib/useMediaQuery';
import styles from './Menu.module.css';

export interface MenuItem {
  key: string;
  label: string;
  icon?: IconName;
  onSelect: () => void;
}

/**
 * A menu button following the WAI-ARIA pattern: arrows move, Escape closes and returns focus. On
 * phones it opens as a sheet from the bottom edge, over a scrim that closes it.
 */
export function Menu({ trigger, label, items, align = 'end' }: { trigger: (props: { onClick: () => void; 'aria-expanded': boolean; 'aria-haspopup': 'menu'; 'aria-controls': string }) => ReactNode; label: string; items: MenuItem[]; align?: 'start' | 'end' }) {
  const [open, setOpen] = useState(false);
  const id = useId();
  const root = useRef<HTMLDivElement>(null);
  const list = useRef<HTMLUListElement>(null);
  // In <body>, so a toolbar's backdrop blur can't hold the sheet inside it.
  const sheet = useMediaQuery('(max-width: 719px)');

  useEffect(() => {
    if (!open) return;
    list.current?.querySelector<HTMLElement>('[role="menuitem"]')?.focus();
    const onPointer = (event: PointerEvent) => {
      const target = event.target as Node;
      if (!root.current?.contains(target) && !list.current?.contains(target)) setOpen(false);
    };
    document.addEventListener('pointerdown', onPointer);
    return () => document.removeEventListener('pointerdown', onPointer);
  }, [open]);

  function close() {
    setOpen(false);
    root.current?.querySelector<HTMLElement>('[aria-haspopup]')?.focus();
  }

  const portal = (menu: ReactNode) => (sheet ? createPortal(menu, document.body) : menu);

  function onKeyDown(event: KeyboardEvent) {
    const entries = Array.from(list.current?.querySelectorAll<HTMLElement>('[role="menuitem"]') ?? []);
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

  return (
    <div className={styles.root} ref={root}>
      {trigger({ onClick: () => setOpen((o) => !o), 'aria-expanded': open, 'aria-haspopup': 'menu', 'aria-controls': id })}
      {/* The scrim takes the tap, so it doesn't also reach what's underneath. */}
      {open && sheet && createPortal(<div className={styles.scrim} aria-hidden="true" onPointerDown={(event) => event.stopPropagation()} onClick={close} />, document.body)}
      {open && portal(
        <ul id={id} ref={list} role="menu" aria-label={label} className={[styles.menu, styles[align]].join(' ')} onKeyDown={onKeyDown}>
          {items.map((item) => (
            <li key={item.key} role="none">
              <button
                type="button"
                role="menuitem"
                tabIndex={-1}
                className={styles.item}
                onClick={() => {
                  setOpen(false);
                  item.onSelect();
                }}
              >
                {item.icon && <Icon name={item.icon} size={18} />}
                {item.label}
              </button>
            </li>
          ))}
        </ul>,
      )}
    </div>
  );
}
