import { Button, EmptyState, Icon, IconButton, KeyFingerprint, Spinner } from '@octapass/ui';
import type { Vault } from '@octapass/vault-client';
import { useState } from 'react';
import { Link } from 'react-router';
import { Alert } from '../../components/Alert';
import { formatDate, t } from '../../i18n';
import { useAction } from '../../lib/useAction';
import { useVaults } from '../../lib/useItems';
import { useSharing, useSharingData } from '../../lib/useSharing';
import { PageHeader } from '../PageHeader';
import { Section } from '../settings/SettingsPage';
import settingsStyles from '../settings/SettingsPage.module.css';
import { CreateVaultDialog } from './CreateVaultDialog';
import { FamilyPanel } from './FamilyPanel';
import { roleLabel } from './roles';
import styles from './Sharing.module.css';

/** Sharing: your fingerprint, the vaults you share, your family and your share links (plan 06). */
export function SharingPage() {
  const sharing = useSharing();
  const [creating, setCreating] = useState(false);

  if (!sharing) {
    return (
      <div className={settingsStyles.page}>
        <PageHeader title={t('sharing.title')} />
        <EmptyState icon="users" title={t('sharing.unavailable')} />
      </div>
    );
  }

  return (
    <div className={settingsStyles.page}>
      <PageHeader
        title={t('sharing.title')}
        subtitle={t('sharing.subtitle')}
        actions={
          <Button size="sm" icon="plus" onClick={() => setCreating(true)}>
            {t('sharing.newVault')}
          </Button>
        }
      />
      <div className={settingsStyles.body}>
        <MyFingerprint />
        <KeyLogSection />
        <SharedVaults />
        <Section id="family" title={t('family.title')}>
          <FamilyPanel />
        </Section>
        <Section id="links" title={t('sharing.links')} description={t('sharing.linksHelp')}>
          <ShareLinks />
        </Section>
      </div>
      <CreateVaultDialog open={creating} onClose={() => setCreating(false)} />
    </div>
  );
}

function KeyLogSection() {
  const sharing = useSharing()!;
  const { busy, run } = useAction();
  const { data: state } = useSharingData((s) => s.getKeyLogState());
  if (!state) return null;
  return (
    <Section id="key-log" title={t('keyLog.title')} description={t('keyLog.help')}>
      <div className={styles.panel}>
        {state.alert && (
          <Alert
            tone="warn"
            action={
              <Button variant="secondary" size="sm" busy={busy === 'dismiss'} onClick={() => void run('dismiss', () => sharing.dismissKeyLogAlert())}>
                {t('keyLog.dismiss')}
              </Button>
            }
          >
            <strong>{t('keyLog.alertTitle')}</strong> {t(`keyLog.alert.${state.alert.kind}`)}
          </Alert>
        )}
        <p>{state.published ? t('keyLog.published') : t('keyLog.notPublished')}</p>
        <p>{state.checkedAt ? t('keyLog.checked', { date: formatDate(state.checkedAt) }) : t('keyLog.neverChecked')}</p>
      </div>
    </Section>
  );
}

function MyFingerprint() {
  const { data: fingerprint } = useSharingData((s) => s.getMyFingerprint());
  return (
    <Section id="fingerprint" title={t('fingerprint.yours')}>
      <div className={styles.mine}>
        {fingerprint ? <KeyFingerprint label={t('fingerprint.yours')} emojiLabel={t('fingerprint.emoji')} digits={fingerprint.digits} emoji={fingerprint.emoji} /> : <Spinner size={20} />}
        <p>{t('fingerprint.yoursHelp')}</p>
      </div>
    </Section>
  );
}

export function vaultIcon(vault: Pick<Vault, 'type' | 'untrusted'>) {
  return vault.untrusted ? 'alert' : vault.type === 'family' ? 'home' : vault.type === 'shared' ? 'users' : 'vault';
}

function SharedVaults() {
  const vaults = useVaults()?.filter((v) => v.type === 'shared');
  return (
    <section className={settingsStyles.section} aria-labelledby="shared-vaults-title">
      <div className={settingsStyles.sectionHead}>
        <h2 id="shared-vaults-title">{t('sharing.vaults')}</h2>
        <p>{t('sharing.vaultsHelp')}</p>
      </div>
      {!vaults ? (
        <Spinner size={20} />
      ) : vaults.length === 0 ? (
        <div className={settingsStyles.card}>
          <p className={styles.empty}>{t('sharing.noVaults')}</p>
        </div>
      ) : (
        <ul className={styles.vaults}>
          {vaults.map((vault) => (
            <li key={vault.id}>
              <Link to={`/sharing/vaults/${vault.id}`} className={styles.vaultCard}>
                <span className={styles.vaultIcon} data-tone={vault.untrusted ? 'warn' : undefined}>
                  <Icon name={vaultIcon(vault)} size={20} />
                </span>
                <span className={styles.vaultText}>
                  <strong>{vault.name}</strong>
                  <span>{vault.untrusted ? t('vault.untrusted') : t('sharing.roleIn', { role: roleLabel(vault.role) })}</span>
                </span>
                <Icon name="chevronRight" size={18} className={styles.chev} />
              </Link>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function ShareLinks() {
  const { data: links } = useSharingData((s) => s.listShareLinks());
  const sharing = useSharing()!;
  const { busy, run } = useAction();

  if (!links) return <p className={styles.empty}>{t('common.loading')}</p>;
  if (links.length === 0) return <p className={styles.empty}>{t('sharing.noLinks')}</p>;
  return (
    <ul className={styles.list}>
      {links.map((link) => {
        const title = link.itemTitle ?? t('sharing.linkItem');
        return (
          <li key={link.id} className={styles.person}>
            <div className={styles.who}>
              <span className={styles.vaultIcon}>
                <Icon name="link" size={18} />
              </span>
              <div className={styles.whoText}>
                {link.itemId ? (
                  <Link to={`/items/all/${link.itemId}`} className={styles.name}>
                    {title}
                  </Link>
                ) : (
                  <span className={styles.name}>{title}</span>
                )}
                <span className={styles.meta}>
                  <span>{t('sharing.linkExpires', { date: formatDate(link.expiresAt, 'long') })}</span>
                  <span>{t('sharing.linkViews', { views: link.views, count: link.maxViews })}</span>
                  {link.passphraseRequired && <span className={`${styles.badge} ${styles.info}`}>{t('sharing.linkPassphrase')}</span>}
                </span>
              </div>
            </div>
            <div className={styles.controls}>
              <IconButton
                icon="trash"
                tone="danger"
                label={t('sharing.revokeLink', { title })}
                disabled={busy === link.id}
                onClick={() => void run(link.id, () => sharing.revokeShareLink(link.id), t('sharing.revoked'))}
              />
            </div>
          </li>
        );
      })}
    </ul>
  );
}
