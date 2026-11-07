import { Button, TextField } from '@octapass/ui';
import type { OrgPolicies, OrgSsoSettings } from '@octapass/vault-client';
import { useEffect, useState, type FormEvent } from 'react';
import { formatDate, t } from '../../i18n';
import { useAction } from '../../lib/useAction';
import { useOrganisationData, useOrganisations } from '../../lib/useOrganisation';
import { Row, Section } from '../settings/SettingsPage';
import styles from '../sharing/Sharing.module.css';

/** The identity provider's settings. SSO adds a sign-in step; it never replaces the master password. */
export function SsoPanel({ policies }: { policies: OrgPolicies }) {
  const organisations = useOrganisations()!;
  const { data, retry } = useOrganisationData((o) => o.getOrgSso());
  const { busy, run } = useAction();
  const [issuer, setIssuer] = useState('');
  const [clientId, setClientId] = useState('');
  const [clientSecret, setClientSecret] = useState('');

  useEffect(() => {
    if (!data) return;
    setIssuer(data.issuer ?? '');
    setClientId(data.clientId ?? '');
  }, [data]);

  function save(event: FormEvent) {
    event.preventDefault();
    void run('save', () => organisations.saveOrgSso({ issuer: issuer.trim(), clientId: clientId.trim(), clientSecret: clientSecret || undefined }), t('organisation.ssoSaved')).then((done) => {
      if (done) setClientSecret('');
    });
  }

  function test() {
    // Opened first, from the click, so a popup blocker lets it through; the URL follows.
    const opened = window.open('', '_blank');
    void run('test', async () => {
      const url = await organisations.testOrgSso();
      if (opened) opened.location.href = url;
      else window.open(url, '_blank', 'noopener,noreferrer');
    });
  }

  if (!data) return <p className={styles.empty}>{t('common.loading')}</p>;
  const settings: OrgSsoSettings = data;
  return (
    <Section id="sso" title={t('organisation.tabSso')} description={t('organisation.ssoHelp')}>
      <Row label={t('organisation.ssoSignInOnly')} description={t('organisation.ssoSignInOnlyHelp')} />
      <Row label={t('organisation.ssoRedirect')} description={settings.callbackUrl} />
      <form className={styles.panel} onSubmit={save}>
        <TextField label={t('organisation.ssoIssuer')} type="url" autoComplete="off" value={issuer} onChange={(e) => setIssuer(e.target.value)} disabled={policies.requireSso} />
        <TextField label={t('organisation.ssoClientId')} autoComplete="off" value={clientId} onChange={(e) => setClientId(e.target.value)} disabled={policies.requireSso} />
        <TextField
          label={t('organisation.ssoClientSecret')}
          hint={settings.hasClientSecret ? t('organisation.ssoSecretKept') : t('organisation.ssoSecretHelp')}
          type="password"
          autoComplete="off"
          value={clientSecret}
          onChange={(e) => setClientSecret(e.target.value)}
          disabled={policies.requireSso}
        />
        {policies.requireSso && <p className={styles.meta}>{t('organisation.ssoLocked')}</p>}
        <div className={styles.controls}>
          <Button type="submit" size="sm" busy={busy === 'save'} disabled={policies.requireSso || !issuer.trim() || !clientId.trim()}>
            {t('organisation.ssoSave')}
          </Button>
          {settings.issuer && (
            <Button type="button" variant="secondary" size="sm" icon="external" busy={busy === 'test'} onClick={test}>
              {t('organisation.ssoTest')}
            </Button>
          )}
          {settings.issuer && !policies.requireSso && (
            <Button type="button" variant="danger" size="sm" busy={busy === 'remove'} onClick={() => void run('remove', () => organisations.removeOrgSso(), t('organisation.ssoRemoved'))}>
              {t('organisation.ssoRemove')}
            </Button>
          )}
          <Button type="button" variant="secondary" size="sm" icon="refresh" onClick={retry}>
            {t('organisation.ssoRefresh')}
          </Button>
        </div>
        <p className={styles.meta}>{settings.testedAt ? t('organisation.ssoTested', { date: formatDate(settings.testedAt, 'long') }) : t('organisation.ssoNotTested')}</p>
      </form>
    </Section>
  );
}
