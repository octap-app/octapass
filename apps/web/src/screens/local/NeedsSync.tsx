import { Button, Icon } from '@octapass/ui';
import { isLocalServer } from '@octapass/vault-client';
import type { ReactNode } from 'react';
import { useNavigate } from 'react-router';
import { useSession } from '../../app/ServiceContext';
import { t } from '../../i18n';
import styles from './local.module.css';

/** What only an account can do. A local vault shows this in its place, never a dead end (plan 05). */
export function AccountOnly({ children }: { children: ReactNode }) {
  const session = useSession();
  return isLocalServer(session.serverUrl) ? <NeedsSync /> : children;
}

export function NeedsSync() {
  const navigate = useNavigate();
  return (
    <div className={styles.needsSync}>
      <Icon name="refresh" size={28} />
      <h2>{t('localVault.needsSync')}</h2>
      <p>{t('localVault.needsSyncBody')}</p>
      <Button icon="refresh" onClick={() => navigate('/local/sync')}>
        {t('localVault.turnOnSync')}
      </Button>
    </div>
  );
}
