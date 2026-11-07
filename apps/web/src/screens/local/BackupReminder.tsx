import { Button } from '@octapass/ui';
import { isLocalServer } from '@octapass/vault-client';
import { useNavigate } from 'react-router';
import { useSession } from '../../app/ServiceContext';
import { Alert } from '../../components/Alert';
import { t } from '../../i18n';
import styles from './local.module.css';
import { daysSince, useLocalVaults } from './useLocalVaults';

/** Every 30 days (plan 01). A working folder keeps `backupDue` off; a broken one doesn't. */
export function BackupReminder() {
  const session = useSession();
  const navigate = useNavigate();
  const { current } = useLocalVaults();
  if (!isLocalServer(session.serverUrl) || !current?.backupDue) return null;
  return (
    <div className={styles.banner}>
      <Alert tone="warn">
        {current.lastBackupAt ? t('localVault.reminder', { count: daysSince(current.lastBackupAt) }) : t('localVault.reminderNever')}{' '}
        <Button variant="ghost" size="sm" onClick={() => navigate('/settings#local')}>
          {t('localVault.backUp')}
        </Button>
      </Alert>
    </div>
  );
}
