import { Button } from '@octapass/ui';
import { useNavigate } from 'react-router';
import { useService } from '../../app/ServiceContext';
import { t } from '../../i18n';
import styles from './local.module.css';
import { useLocalVaults } from './useLocalVaults';

/** On the first screen, next to signing in (plan 05): the vaults here, a new one, or a backup. */
export function LocalChoices() {
  const service = useService();
  const navigate = useNavigate();
  const { vaults } = useLocalVaults();
  if (!service.local) return null;
  return (
    <div className={styles.choices}>
      {vaults.length > 0 && <LocalVaultList vaults={vaults} heading={t('localVault.onThisDevice')} />}
      <Button size="lg" block variant="secondary" icon="lock" onClick={() => navigate('/local/new')}>
        {t('localVault.useOnThisDevice')}
      </Button>
      <p>{t('localVault.useOnThisDeviceHelp')}</p>
      <button type="button" className={styles.link} onClick={() => navigate('/local/restore')}>
        {t('localVault.restoreBackup')}
      </button>
    </div>
  );
}

export function LocalVaultList({ vaults, heading }: { vaults: { id: string; name: string }[]; heading: string }) {
  const service = useService();
  return (
    <section aria-label={heading}>
      <ul className={styles.vaults}>
        {vaults.map((vault) => (
          <li key={vault.id} className={styles.vault}>
            <bdi>{vault.name}</bdi>
            <Button variant="ghost" size="sm" onClick={() => void service.local?.switchTo(vault.id)}>
              {t('localVault.open')}
            </Button>
          </li>
        ))}
      </ul>
    </section>
  );
}
