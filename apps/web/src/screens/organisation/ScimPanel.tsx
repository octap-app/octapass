import { Button, TextField } from '@octapass/ui';
import { useState, type FormEvent } from 'react';
import { formatDate, t } from '../../i18n';
import { useCopy } from '../../lib/clipboard';
import { useAction } from '../../lib/useAction';
import { useOrganisationData, useOrganisations } from '../../lib/useOrganisation';
import { Row, Section } from '../settings/SettingsPage';
import styles from '../sharing/Sharing.module.css';

/**
 * SCIM provisioning: the identity provider invites, groups and removes members with a token made
 * here. It never opens a vault: a key holder still reviews every grant.
 */
export function ScimPanel() {
  const organisations = useOrganisations()!;
  const { data } = useOrganisationData((o) => o.getOrgScim());
  const { busy, run } = useAction();
  const copy = useCopy();
  const [name, setName] = useState('');
  const [secret, setSecret] = useState<string>();

  function create(event: FormEvent) {
    event.preventDefault();
    void run('create', async () => {
      const created = await organisations.createOrgScimToken(name);
      setSecret(created.secret);
      setName('');
    });
  }

  if (!data) return <p className={styles.empty}>{t('common.loading')}</p>;
  return (
    <Section id="scim" title={t('organisation.tabScim')} description={t('organisation.scimHelp')}>
      <Row label={t('organisation.scimWhatItDoes')} description={t('organisation.scimWhatItDoesHelp')} />
      <Row label={t('organisation.scimBaseUrl')} description={data.baseUrl}>
        <Button type="button" variant="secondary" size="sm" icon="copy" onClick={() => void copy(data.baseUrl, t('organisation.scimBaseUrl'))}>
          {t('organisation.scimCopy')}
        </Button>
      </Row>
      {secret && (
        <div className={styles.panel}>
          <TextField label={t('organisation.scimNewToken')} hint={t('organisation.scimNewTokenHelp')} mono readOnly value={secret} />
          <div className={styles.controls}>
            <Button type="button" size="sm" icon="copy" onClick={() => void copy(secret, t('organisation.scimNewToken'), { secret: true })}>
              {t('organisation.scimCopy')}
            </Button>
            <Button type="button" variant="secondary" size="sm" onClick={() => setSecret(undefined)}>
              {t('organisation.scimDone')}
            </Button>
          </div>
        </div>
      )}
      {data.tokens.length === 0 ? (
        <p className={styles.empty}>{t('organisation.scimNoTokens')}</p>
      ) : (
        <ul className={styles.list}>
          {data.tokens.map((token) => (
            <li key={token.id} className={styles.person}>
              <div className={styles.whoText}>
                <span className={styles.name}>{token.name}</span>
                <span className={styles.meta}>
                  <span>{t('organisation.scimCreated', { date: formatDate(token.createdAt, 'long') })}</span>
                  <span>{token.lastUsedAt ? t('organisation.scimLastUsed', { date: formatDate(token.lastUsedAt, 'long') }) : t('organisation.scimNeverUsed')}</span>
                </span>
              </div>
              <Button
                type="button"
                variant="danger"
                size="sm"
                busy={busy === token.id}
                onClick={() => void run(token.id, () => organisations.revokeOrgScimToken(token.id), t('organisation.scimRevoked'))}
              >
                {t('organisation.scimRevoke')}
              </Button>
            </li>
          ))}
        </ul>
      )}
      <form className={styles.panel} onSubmit={create}>
        <TextField label={t('organisation.scimTokenName')} hint={t('organisation.scimTokenNameHelp')} autoComplete="off" value={name} onChange={(e) => setName(e.target.value)} />
        <div className={styles.controls}>
          <Button type="submit" size="sm" busy={busy === 'create'} disabled={!name.trim()}>
            {t('organisation.scimCreate')}
          </Button>
        </div>
      </form>
    </Section>
  );
}
