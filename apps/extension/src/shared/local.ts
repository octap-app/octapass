/** Stands in for the server URL in a local vault's session, so pages can tell it apart from an account. */
export const LOCAL_SERVER = 'local:this-device';

/** What the service worker remembers about a local vault, besides the vault itself. */
export interface LocalMeta {
  createdAt: string;
  lastBackupAt?: string;
  /**
   * Bound to the chip of the desktop app on this computer (plan 05): the app needs both to give
   * back the secret. Neither is one.
   */
  chip?: { vaultId: string; context: string };
}

/** A local vault without a backup for this long gets a reminder (plan 01). */
export const BACKUP_REMINDER_DAYS = 30;
