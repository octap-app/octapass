import { useEffect, useRef } from 'react';

export type ShortcutMap = Partial<Record<string, (event: KeyboardEvent) => void>>;

function isTyping(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  return target.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName);
}

/**
 * Single-key shortcuts ("/", "n") that stay out of the way while the user is typing in a field.
 * Keys are matched on `event.key`; "mod+c" means Cmd on Apple platforms and Ctrl elsewhere.
 */
export function useShortcuts(map: ShortcutMap): void {
  const latest = useRef(map);
  latest.current = map;

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.defaultPrevented || event.altKey) return;
      const mod = event.metaKey || event.ctrlKey;
      const key = (mod ? 'mod+' : '') + event.key.toLowerCase();
      const handler = latest.current[key];
      if (!handler || (!mod && isTyping(event.target))) return;
      handler(event);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);
}
