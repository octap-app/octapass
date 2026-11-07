import { Dialog, useToast } from '@octapass/ui';
import type { HealthEntry, LoginDetails } from '@octapass/vault-client';
import { useState } from 'react';
import { useService } from '../../app/ServiceContext';
import { Alert } from '../../components/Alert';
import { t } from '../../i18n';
import { errorMessage } from '../../lib/errors';
import { useHealth } from '../../lib/health';
import { GeneratorPanel } from '../generator/GeneratorPanel';
import styles from './HealthPage.module.css';

/**
 * The second half of "Change password": the site's own page is open in another tab, so this makes
 * the new password and saves it. Saving keeps the old one in the item's password history, so saving
 * too early loses nothing.
 */
export function ChangePasswordDialog({ entry, onClose }: { entry: HealthEntry; onClose: () => void }) {
  const service = useService();
  const toast = useToast();
  const { refresh } = useHealth();
  const [error, setError] = useState<unknown>();

  const save = async (password: string) => {
    setError(undefined);
    try {
      const item = await service.getItem(entry.itemId);
      await service.saveItem({ ...item, details: { ...(item.details as LoginDetails), password } });
      toast({ message: t('health.change.saved'), tone: 'success' });
      refresh();
      onClose();
    } catch (e) {
      setError(e);
    }
  };

  return (
    <Dialog open onClose={onClose} size="md" title={t('health.change.title', { title: entry.title })} description={t('health.change.steps')} closeLabel={t('common.close')}>
      <div className={styles.changeBody}>
        {entry.changePasswordUrl && (
          <p className={styles.help}>
            {t('health.change.notFound')}{' '}
            <a href={entry.changePasswordUrl} target="_blank" rel="noopener noreferrer">
              {t('health.change.openAgain')}
            </a>
          </p>
        )}
        {error !== undefined && <Alert>{errorMessage(error)}</Alert>}
        <GeneratorPanel useLabel={t('health.change.save')} onUse={(password) => void save(password)} />
      </div>
    </Dialog>
  );
}
