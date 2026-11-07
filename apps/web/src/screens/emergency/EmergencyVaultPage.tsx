import { Avatar, EmptyState, Icon, Spinner } from '@octapass/ui';
import type { EmergencyVaultView, Item } from '@octapass/vault-client';
import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router';
import { Alert } from '../../components/Alert';
import { t } from '../../i18n';
import { errorMessage } from '../../lib/errors';
import { displayVault } from '../../lib/useItems';
import { useSharing } from '../../lib/useSharing';
import { PageHeader } from '../PageHeader';
import { ReadOnlyFiles } from '../vault/Files';
import { TypeFields } from '../vault/ItemDetail';
import styles from './EmergencyVaultPage.module.css';

/** As a trusted contact, after release: the grantor's vaults, read-only, decrypted on this device. */
export function EmergencyVaultPage() {
  const { contactId = '' } = useParams();
  const sharing = useSharing();
  const [view, setView] = useState<EmergencyVaultView>();
  const [error, setError] = useState<unknown>();
  const [selected, setSelected] = useState<Item>();

  useEffect(() => {
    if (!sharing) return;
    let live = true;
    sharing.openEmergencyAccess(contactId).then(
      (next) => live && setView(next),
      (e: unknown) => live && setError(e),
    );
    return () => {
      live = false;
    };
  }, [sharing, contactId]);

  const back = (
    <Link to="/emergency" className={styles.back}>
      <Icon name="chevronLeft" size={16} />
      {t('emergency.vaultBack')}
    </Link>
  );

  if (error || !sharing) {
    return (
      <div className={styles.page}>
        <PageHeader title={t('emergency.title')} subtitle={back} />
        <EmptyState icon="alert" title={t('emergency.vaultFailed')}>
          {errorMessage(error)}
        </EmptyState>
      </div>
    );
  }
  if (!view) {
    return (
      <div className={styles.page}>
        <PageHeader title={t('emergency.title')} subtitle={back} />
        <div className={styles.loading}>
          <Spinner size={24} />
        </div>
      </div>
    );
  }

  const items = [...view.items].sort((a, b) => a.overview.title.localeCompare(b.overview.title));
  return (
    <div className={styles.page}>
      <PageHeader title={t('emergency.vaultTitle', { email: view.contact.grantorEmail })} subtitle={back} />
      <div className={styles.body}>
        <Alert tone="warn">{t('emergency.vaultReadOnly')}</Alert>
        {items.length === 0 ? (
          <EmptyState icon="vault" title={t('emergency.vaultEmpty')} />
        ) : (
          <div className={styles.split}>
            <div className={styles.lists}>
              {view.vaults.map((vault) => (
                <section key={vault.id} aria-labelledby={`vault-${vault.id}`}>
                  <h2 id={`vault-${vault.id}`} className={styles.vaultName}>
                    {displayVault(vault).name}
                  </h2>
                  <ul className={styles.items}>
                    {items
                      .filter((item) => item.vaultId === vault.id)
                      .map((item) => (
                        <li key={item.id}>
                          <button type="button" className={styles.item} aria-pressed={selected?.id === item.id} onClick={() => setSelected(item)}>
                            <Avatar name={item.overview.title} size="sm" />
                            <span className={styles.itemText}>
                              <strong>{item.overview.title || t('detail.untitled')}</strong>
                              {item.overview.subtitle && <span>{item.overview.subtitle}</span>}
                            </span>
                          </button>
                        </li>
                      ))}
                  </ul>
                </section>
              ))}
            </div>
            <section className={styles.detail} aria-label={t('detail.region')} aria-live="polite">
              {selected ? (
                <>
                  <h2 className={styles.detailTitle}>
                    <Avatar name={selected.overview.title} size="lg" />
                    {selected.overview.title || t('detail.untitled')}
                  </h2>
                  <TypeFields item={selected} />
                  <ReadOnlyFiles key={selected.id} item={selected} get={(attachmentId) => sharing.getEmergencyAttachment(contactId, selected.id, attachmentId)} />
                </>
              ) : (
                <p className={styles.hint}>{t('emergency.vaultSelect')}</p>
              )}
            </section>
          </div>
        )}
      </div>
    </div>
  );
}
