import { Button, Segmented, TextArea, TextField } from '@octapass/ui';
import type { OrgPolicies, OrgSsoSettings } from '@octapass/vault-client';
import { useEffect, useState, type FormEvent } from 'react';
import { formatDate, t } from '../../i18n';
import { useAction } from '../../lib/useAction';
import { useOrganisationData, useOrganisations } from '../../lib/useOrganisation';
import { Row, Section } from '../settings/SettingsPage';
import styles from '../sharing/Sharing.module.css';

type Protocol = 'oidc' | 'saml';

/**
 * The identity provider's settings, by OpenID Connect or SAML 2.0. SSO adds a sign-in step; it never
 * replaces the master password.
 */
export function SsoPanel({ policies }: { policies: OrgPolicies }) {
  const organisations = useOrganisations()!;
  const { data, retry } = useOrganisationData((o) => o.getOrgSso());
  const { busy, run } = useAction();
  const [protocol, setProtocol] = useState<Protocol>('oidc');
  const [issuer, setIssuer] = useState('');
  const [clientId, setClientId] = useState('');
  const [clientSecret, setClientSecret] = useState('');
  const [metadataXml, setMetadataXml] = useState('');
  const [entityId, setEntityId] = useState('');
  const [ssoUrl, setSsoUrl] = useState('');
  const [certificate, setCertificate] = useState('');

  useEffect(() => {
    if (!data) return;
    setProtocol(data.protocol ?? 'oidc');
    setIssuer(data.issuer ?? '');
    setClientId(data.clientId ?? '');
    setEntityId(data.saml?.entityId ?? '');
    setSsoUrl(data.saml?.ssoUrl ?? '');
  }, [data]);

  function saveOidc(event: FormEvent) {
    event.preventDefault();
    void run('save', () => organisations.saveOrgSso({ issuer: issuer.trim(), clientId: clientId.trim(), clientSecret: clientSecret || undefined }), t('organisation.ssoSaved')).then((done) => {
      if (done) setClientSecret('');
    });
  }

  function saveSaml(event: FormEvent) {
    event.preventDefault();
    const input = metadataXml.trim() ? { metadataXml: metadataXml.trim() } : { entityId: entityId.trim(), ssoUrl: ssoUrl.trim(), certificates: [certificate.trim()] };
    void run('save', () => organisations.saveOrgSaml(input), t('organisation.ssoSaved')).then((done) => {
      if (done) {
        setMetadataXml('');
        setCertificate('');
      }
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
  const locked = policies.requireSso;
  const canSaveSaml = Boolean(metadataXml.trim()) || Boolean(entityId.trim() && ssoUrl.trim() && certificate.trim());
  const controls = (
    <div className={styles.controls}>
      <Button type="submit" size="sm" busy={busy === 'save'} disabled={locked || (protocol === 'oidc' ? !issuer.trim() || !clientId.trim() : !canSaveSaml)}>
        {t('organisation.ssoSave')}
      </Button>
      {settings.protocol && (
        <Button type="button" variant="secondary" size="sm" icon="external" busy={busy === 'test'} onClick={test}>
          {t('organisation.ssoTest')}
        </Button>
      )}
      {settings.protocol && !locked && (
        <Button type="button" variant="danger" size="sm" busy={busy === 'remove'} onClick={() => void run('remove', () => organisations.removeOrgSso(), t('organisation.ssoRemoved'))}>
          {t('organisation.ssoRemove')}
        </Button>
      )}
      <Button type="button" variant="secondary" size="sm" icon="refresh" onClick={retry}>
        {t('organisation.ssoRefresh')}
      </Button>
    </div>
  );
  return (
    <Section id="sso" title={t('organisation.tabSso')} description={t('organisation.ssoHelp')}>
      <Row label={t('organisation.ssoSignInOnly')} description={t('organisation.ssoSignInOnlyHelp')} />
      <Segmented
        label={t('organisation.ssoProtocol')}
        options={[
          { value: 'oidc', label: t('organisation.ssoOidc') },
          { value: 'saml', label: t('organisation.ssoSaml') },
        ]}
        value={protocol}
        onChange={setProtocol}
      />
      {settings.protocol && settings.protocol !== protocol && <p className={styles.meta}>{t('organisation.ssoReplaces')}</p>}
      {protocol === 'oidc' ? (
        <>
          <Row label={t('organisation.ssoRedirect')} description={settings.callbackUrl} />
          <form className={styles.panel} onSubmit={saveOidc}>
            <TextField label={t('organisation.ssoIssuer')} type="url" autoComplete="off" value={issuer} onChange={(e) => setIssuer(e.target.value)} disabled={locked} />
            <TextField label={t('organisation.ssoClientId')} autoComplete="off" value={clientId} onChange={(e) => setClientId(e.target.value)} disabled={locked} />
            <TextField
              label={t('organisation.ssoClientSecret')}
              hint={settings.protocol === 'oidc' && settings.hasClientSecret ? t('organisation.ssoSecretKept') : t('organisation.ssoSecretHelp')}
              type="password"
              autoComplete="off"
              value={clientSecret}
              onChange={(e) => setClientSecret(e.target.value)}
              disabled={locked}
            />
            {locked && <p className={styles.meta}>{t('organisation.ssoLocked')}</p>}
            {controls}
            <p className={styles.meta}>{settings.testedAt ? t('organisation.ssoTested', { date: formatDate(settings.testedAt, 'long') }) : t('organisation.ssoNotTested')}</p>
          </form>
        </>
      ) : (
        <>
          <Row label={t('organisation.samlSpEntity')} description={settings.samlServiceProvider.entityId} />
          <Row label={t('organisation.samlAcs')} description={settings.samlServiceProvider.acsUrl} />
          {settings.saml && (
            <Row
              label={t('organisation.samlSaved', { entity: settings.saml.entityId })}
              description={settings.saml.certificates.map((certificate) => t('organisation.samlCertificate', { sha256: certificate.sha256 })).join(' · ')}
            />
          )}
          <form className={styles.panel} onSubmit={saveSaml}>
            <TextArea label={t('organisation.samlMetadata')} hint={t('organisation.samlMetadataHelp')} mono rows={4} value={metadataXml} onChange={(e) => setMetadataXml(e.target.value)} disabled={locked} />
            <TextField label={t('organisation.samlEntityId')} autoComplete="off" value={entityId} onChange={(e) => setEntityId(e.target.value)} disabled={locked || Boolean(metadataXml.trim())} />
            <TextField label={t('organisation.samlSsoUrl')} type="url" autoComplete="off" value={ssoUrl} onChange={(e) => setSsoUrl(e.target.value)} disabled={locked || Boolean(metadataXml.trim())} />
            <TextArea
              label={t('organisation.samlCertificateField')}
              hint={t('organisation.samlCertificateHelp')}
              mono
              rows={3}
              value={certificate}
              onChange={(e) => setCertificate(e.target.value)}
              disabled={locked || Boolean(metadataXml.trim())}
            />
            {locked && <p className={styles.meta}>{t('organisation.ssoLocked')}</p>}
            {controls}
            <p className={styles.meta}>{settings.testedAt ? t('organisation.ssoTested', { date: formatDate(settings.testedAt, 'long') }) : t('organisation.ssoNotTested')}</p>
          </form>
        </>
      )}
    </Section>
  );
}
