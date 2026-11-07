import { Avatar, Button, Checkbox, KeyFingerprint } from '@octapass/ui';
import type { OrgAccessGrant, OrgAccessReview } from '@octapass/vault-client';
import { useState } from 'react';
import { t } from '../../i18n';
import { useAction } from '../../lib/useAction';
import { useOrganisationData, useOrganisations } from '../../lib/useOrganisation';
import { Section } from '../settings/SettingsPage';
import { roleLabel } from '../sharing/roles';
import styles from '../sharing/Sharing.module.css';

const vaultName = (vault: Pick<OrgAccessReview, 'vaultName' | 'shortId'>) => vault.vaultName ?? t('organisation.vaultWithId', { id: vault.shortId });

/**
 * Vaults waiting for a key holder. The list comes from the server, so a person confirms everyone
 * here before this device seals anything: a hostile server could otherwise add itself (plan 03).
 */
export function AccessReview() {
  const { data } = useOrganisationData((o) => o.getOrgAccess());
  if (!data || data.length === 0) return null;
  return (
    <Section id="access" title={t('organisation.accessTitle')} description={t('organisation.accessHelp')}>
      <ul className={styles.list}>
        {data.map((vault) => (
          <li key={vault.vaultId}>{vault.canApply ? <Applicable vault={vault} /> : <Waiting vault={vault} />}</li>
        ))}
      </ul>
    </Section>
  );
}

function Waiting({ vault }: { vault: OrgAccessReview }) {
  return (
    <div className={styles.person}>
      <div className={styles.whoText}>
        <span className={styles.name}>{vaultName(vault)}</span>
        <span className={styles.meta}>{t('organisation.accessWaiting', { count: vault.grants.length })}</span>
      </div>
    </div>
  );
}

function Applicable({ vault }: { vault: OrgAccessReview }) {
  const organisations = useOrganisations()!;
  const { busy, run } = useAction();
  const [confirmed, setConfirmed] = useState<Set<string>>(new Set());
  const chosen = vault.grants.filter((grant) => confirmed.has(grant.accountId));

  function toggle(grant: OrgAccessGrant, on: boolean) {
    const next = new Set(confirmed);
    if (on) next.add(grant.accountId);
    else next.delete(grant.accountId);
    setConfirmed(next);
  }

  return (
    <div className={styles.panel}>
      <h3>{vaultName(vault)}</h3>
      {vault.grants.map((grant) => (
        <div key={grant.accountId} className={styles.person}>
          <div className={styles.who}>
            <Avatar name={grant.email} />
            <div className={styles.whoText}>
              <span className={styles.name}>{grant.email}</span>
              <span className={styles.meta}>
                <span>{roleLabel(grant.role)}</span>
                {grant.upgrade && <span>{t('organisation.accessUpgrade')}</span>}
                {grant.verified && <span className={`${styles.badge} ${styles.ok}`}>{t('fingerprint.verified')}</span>}
              </span>
            </div>
          </div>
          <KeyFingerprint label={t('fingerprint.title')} emojiLabel={t('fingerprint.emoji')} digits={grant.fingerprint.digits} emoji={grant.fingerprint.emoji} />
          <Checkbox
            label={t('organisation.accessConfirm', { email: grant.email })}
            checked={confirmed.has(grant.accountId)}
            disabled={grant.keyChanged}
            onChange={(event) => toggle(grant, event.target.checked)}
          />
          {grant.keyChanged && <p className={styles.meta}>{t('organisation.accessKeyChanged')}</p>}
        </div>
      ))}
      <div className={styles.controls}>
        {vault.grants.length > 0 && (
          <Button size="sm" disabled={chosen.length === 0} busy={busy === 'apply'} onClick={() => void run('apply', () => organisations.applyOrgAccess(vault.vaultId, chosen), t('organisation.accessApplied'))}>
            {t('organisation.accessApply', { count: chosen.length })}
          </Button>
        )}
        {vault.rotate && (
          <Button variant="secondary" size="sm" icon="refresh" busy={busy === 'rotate'} onClick={() => void run('rotate', () => organisations.rotateOrgVault(vault.vaultId), t('organisation.rotated'))}>
            {t('organisation.rotate')}
          </Button>
        )}
      </div>
    </div>
  );
}
