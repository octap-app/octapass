import { Alert } from '@octapass/web/src/components/Alert';
import { useEffect, useState } from 'react';
import { Link } from 'react-router';
import { BACKUP_REMINDER_DAYS } from '../../shared/local';
import { tx } from '../../i18n';
import { useExtension } from '../ExtensionContext';
import styles from './local.module.css';

const daysSince = (iso: string) => Math.floor((Date.now() - Date.parse(iso)) / 86_400_000);

/** A nudge when a local vault hasn't been backed up for a month (plan 01: "Last backup 34 days ago"). */
export function BackupReminder({ itemCount }: { itemCount: number }) {
  const { api } = useExtension();
  const [message, setMessage] = useState<string>();
  useEffect(() => {
    void api.localInfo().then(({ lastBackupAt, createdAt }) => {
      if (lastBackupAt && daysSince(lastBackupAt) >= BACKUP_REMINDER_DAYS) setMessage(tx('local.reminder', { count: daysSince(lastBackupAt) }));
      else if (!lastBackupAt && createdAt && daysSince(createdAt) >= BACKUP_REMINDER_DAYS) setMessage(tx('local.reminderNever'));
    });
  }, [api]);
  if (!message || itemCount === 0) return null;
  return (
    <div className={styles.banner}>
      <Alert tone="warn" action={<Link to="/settings#local">{tx('local.backUp')}</Link>}>
        {message}
      </Alert>
    </div>
  );
}
