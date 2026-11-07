import { useToast } from '@octapass/ui';
import { useCallback } from 'react';
import { t } from '../i18n';
import { useRecordItemUse } from './usage';

export const CLIPBOARD_CLEAR_MS = 30_000;

let pendingClear: ReturnType<typeof setTimeout> | undefined;
let lastCopied: string | undefined;

/**
 * Copies a value and clears the clipboard 30 seconds later. Browsers only let a page write to the
 * clipboard while it has focus, so if the tab is in the background at that moment the clear runs
 * as soon as the user comes back.
 */
export async function copyWithAutoClear(value: string, clearAfterMs = CLIPBOARD_CLEAR_MS): Promise<void> {
  await navigator.clipboard.writeText(value);
  lastCopied = value;
  clearTimeout(pendingClear);
  pendingClear = setTimeout(clearClipboard, clearAfterMs);
}

async function clearClipboard(): Promise<void> {
  if (lastCopied === undefined) return;
  if (!document.hasFocus()) {
    window.addEventListener('focus', () => void clearClipboard(), { once: true });
    return;
  }
  try {
    await navigator.clipboard.writeText('');
    lastCopied = undefined;
  } catch {
    window.addEventListener('focus', () => void clearClipboard(), { once: true });
  }
}

/**
 * Copy with a spoken confirmation: "Password copied. Clears in 30 seconds." Inside an item
 * (`ItemUseProvider`), a copy counts as using it, for Frequently used and Recently used.
 */
export function useCopy(): (value: string, what: string, options?: { secret?: boolean }) => Promise<void> {
  const toast = useToast();
  const recordUse = useRecordItemUse();
  return useCallback(
    async (value, what, { secret = true } = {}) => {
      try {
        if (secret) await copyWithAutoClear(value);
        else await navigator.clipboard.writeText(value);
        toast({ message: secret ? t('copy.copiedSecret', { what }) : t('copy.copied', { what }), tone: 'success', icon: 'copy' });
      } catch {
        toast({ message: t('copy.failed'), tone: 'danger' });
        return;
      }
      recordUse();
    },
    [toast, recordUse],
  );
}
