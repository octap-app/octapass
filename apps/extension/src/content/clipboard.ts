// Copies a one-time code the page couldn't take, and clears it again after 30 seconds. A page may
// only write to the clipboard while it has focus, so a clear that comes too early waits for focus.

const CLEAR_AFTER_MS = 30_000;
let timer: ReturnType<typeof setTimeout> | undefined;

async function clear(): Promise<void> {
  if (!document.hasFocus()) {
    window.addEventListener('focus', () => void clear(), { once: true });
    return;
  }
  await navigator.clipboard.writeText('').catch(() => undefined);
}

export async function copyCode(code: string): Promise<void> {
  await navigator.clipboard.writeText(code);
  clearTimeout(timer);
  timer = setTimeout(() => void clear(), CLEAR_AFTER_MS);
}
