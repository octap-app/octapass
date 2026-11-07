/** Every 30 seconds while the page is visible. */
export const SYNC_INTERVAL_MS = 30_000;

/**
 * Calls `sync` when the page regains focus or becomes visible, and periodically while it's
 * visible. Returns a function that stops watching.
 */
export function watchPage(sync: () => void, intervalMs = SYNC_INTERVAL_MS): () => void {
  const visible = () => document.visibilityState === 'visible';
  const onVisibility = () => {
    if (visible()) sync();
  };
  const timer = setInterval(() => {
    if (visible()) sync();
  }, intervalMs);
  window.addEventListener('focus', sync);
  document.addEventListener('visibilitychange', onVisibility);
  return () => {
    clearInterval(timer);
    window.removeEventListener('focus', sync);
    document.removeEventListener('visibilitychange', onVisibility);
  };
}
