import { Avatar, Button, Icon, IconButton, Select, TextField, useToast } from '@octapass/ui';
import { canManageAlias, MASKED_EMAIL_PROVIDERS, providerInfo, usableIn, type AliasRef, type MaskedAlias, type MaskedEmailConnection, type MaskedEmailProviderId, type RecoveryContact } from '@octapass/vault-client';
import { useState, type FormEvent } from 'react';
import { Link } from 'react-router';
import { useService } from '../../app/ServiceContext';
import { Alert } from '../../components/Alert';
import { ConfirmDialog } from '../../components/ConfirmDialog';
import { PasswordInput } from '../../components/PasswordInput';
import { t } from '../../i18n';
import { useCopy } from '../../lib/clipboard';
import { errorMessage } from '../../lib/errors';
import { useHealth } from '../../lib/health';
import { providerName, useAliasChange, useConnections, useCreateAlias } from '../../lib/maskedEmail';
import { PageHeader } from '../PageHeader';
import { Row, Section } from '../settings/SettingsPage';
import settings from '../settings/SettingsPage.module.css';
import styles from './MaskedEmailPage.module.css';

export function MaskedEmailPage() {
  return (
    <div className={settings.page}>
      <PageHeader title={t('maskedEmail.title')} subtitle={t('maskedEmail.subtitle')} />
      <div className={settings.body}>
        <ProvidersSection />
        <Section title={t('maskedEmail.make')}>
          <AliasMaker />
        </Section>
        <AliasesSection />
      </div>
    </div>
  );
}

/** Connected providers and the form to connect one. Also in the extension's settings. */
export function ProvidersSection({ id }: { id?: string }) {
  const masked = useService().maskedEmail;
  const connections = useConnections();
  const toast = useToast();
  const [leaving, setLeaving] = useState<MaskedEmailConnection>();
  if (!masked) return null;

  return (
    <Section id={id} title={t('maskedEmail.providers')} description={t('maskedEmail.providersHelp')}>
      {connections?.length === 0 && <Row label={t('maskedEmail.none')} />}
      {connections?.map((connection) => (
        <Row
          key={connection.itemId}
          label={
            <span className={styles.provider}>
              <Avatar name={providerName(connection.provider)} size="sm" />
              {providerName(connection.provider)}
            </span>
          }
          description={[connection.domain, connection.baseUrl && new URL(connection.baseUrl).host, !connection.usableHere && t('maskedEmail.blockedHere')].filter(Boolean).join(' · ') || undefined}
        >
          <Button variant="secondary" size="sm" onClick={() => setLeaving(connection)}>
            {t('maskedEmail.disconnect')}
          </Button>
        </Row>
      ))}
      <ConnectForm />
      <ConfirmDialog
        open={Boolean(leaving)}
        title={t('maskedEmail.disconnectTitle', { provider: leaving ? providerName(leaving.provider) : '' })}
        confirmLabel={t('maskedEmail.disconnect')}
        onConfirm={async () => {
          await masked.disconnect(leaving!.itemId);
          toast({ message: t('maskedEmail.disconnected', { provider: providerName(leaving!.provider) }), tone: 'success' });
        }}
        onClose={() => setLeaving(undefined)}
      >
        <p>{t('maskedEmail.disconnectBody', { provider: leaving ? providerName(leaving.provider) : '' })}</p>
      </ConfirmDialog>
    </Section>
  );
}

function ConnectForm() {
  const masked = useService().maskedEmail!;
  const toast = useToast();
  const [provider, setProvider] = useState<MaskedEmailProviderId>('simplelogin');
  const [token, setToken] = useState('');
  const [domain, setDomain] = useState('');
  const [baseUrl, setBaseUrl] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const info = providerInfo(provider);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(undefined);
    try {
      await masked.connect({ provider, token, ...(domain.trim() ? { domain } : {}), ...(baseUrl.trim() ? { baseUrl } : {}) });
      toast({ message: t('maskedEmail.connected', { provider: info.name }), tone: 'success' });
      setToken('');
      setDomain('');
      setBaseUrl('');
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className={styles.connect} onSubmit={(e) => void submit(e)} aria-label={t('maskedEmail.connect')}>
      <p className={styles.connectTitle}>{t('maskedEmail.connect')}</p>
      <Select label={t('maskedEmail.provider')} value={provider} onChange={(e) => setProvider(e.target.value as MaskedEmailProviderId)} options={MASKED_EMAIL_PROVIDERS.map((p) => ({ value: p.id, label: p.name }))} />
      {!usableIn(masked.context, provider) && (
        <Alert tone="info">
          <b>{t('maskedEmail.blockedHere')}.</b> {t('maskedEmail.blockedHereBody', { provider: info.name })}
        </Alert>
      )}
      <PasswordInput
        label={t('maskedEmail.token')}
        autoComplete="off"
        required
        value={token}
        onChange={(e) => setToken(e.target.value)}
        hint={
          <>
            {t('maskedEmail.tokenHint', { provider: info.name })}{' '}
            <a href={info.tokenUrl} target="_blank" rel="noopener noreferrer">
              {t('maskedEmail.getToken')}
            </a>
          </>
        }
      />
      {info.needsDomain && <TextField label={t('maskedEmail.domain')} required dir="ltr" spellCheck={false} autoComplete="off" value={domain} onChange={(e) => setDomain(e.target.value)} hint={t('maskedEmail.domainHint')} />}
      {info.defaultBaseUrl && (
        <TextField
          label={t('maskedEmail.selfHosted')}
          type="url"
          inputMode="url"
          dir="ltr"
          spellCheck={false}
          placeholder={info.defaultBaseUrl}
          value={baseUrl}
          onChange={(e) => setBaseUrl(e.target.value)}
          hint={t('maskedEmail.selfHostedHint', { provider: info.name })}
        />
      )}
      {error && <Alert>{error}</Alert>}
      <div>
        <Button type="submit" busy={busy} icon="plus">
          {t('maskedEmail.connectButton')}
        </Button>
      </div>
      <p className={styles.note}>{t('maskedEmail.whereItWorks')}</p>
    </form>
  );
}

/** "Use a masked email" for a site the user types: the generator's counterpart for email addresses. */
export function AliasMaker({ initialSite = '', setupPath = '/masked-email' }: { initialSite?: string; setupPath?: string }) {
  const connections = useConnections();
  const { create, busy } = useCreateAlias();
  const copy = useCopy();
  const [site, setSite] = useState(initialSite);
  const [connectionId, setConnectionId] = useState('');
  const [alias, setAlias] = useState<MaskedAlias>();

  if (!connections) return null;
  if (connections.length === 0) {
    return (
      <div className={styles.maker}>
        <p className={styles.note}>{t('errors.maskedEmailNotSetUp')}</p>
        <div>
          <Link to={setupPath} className={styles.link}>
            {t('maskedEmail.connect')}
          </Link>
        </div>
      </div>
    );
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    const made = await create(site, connectionId || undefined);
    if (made) setAlias(made);
  }

  return (
    <form className={styles.maker} onSubmit={(e) => void submit(e)} aria-label={t('maskedEmail.make')}>
      <TextField label={t('maskedEmail.site')} required dir="ltr" inputMode="url" spellCheck={false} autoComplete="off" placeholder={t('maskedEmail.sitePlaceholder')} value={site} onChange={(e) => setSite(e.target.value)} />
      {connections.length > 1 && (
        <Select
          label={t('maskedEmail.useWith')}
          value={connectionId}
          onChange={(e) => setConnectionId(e.target.value)}
          options={[{ value: '', label: providerName(connections.find((c) => c.usableHere)?.provider ?? connections[0]!.provider) }, ...connections.map((c) => ({ value: c.itemId, label: [providerName(c.provider), c.domain].filter(Boolean).join(' · '), disabled: !c.usableHere }))]}
        />
      )}
      <div>
        <Button type="submit" icon="mail" busy={busy}>
          {t('editor.useMaskedEmail')}
        </Button>
      </div>
      {alias && (
        <div className={styles.result} aria-live="polite">
          <span className={styles.resultText}>
            <small>{t('maskedEmail.created')}</small>
            <bdi dir="ltr" className="mono">
              {alias.email}
            </bdi>
          </span>
          <IconButton icon="copy" label={t('copy.action', { what: t('fields.email') })} onClick={() => void copy(alias.email, t('fields.email'), { secret: false })} />
        </div>
      )}
    </form>
  );
}

/**
 * Turn off, turn on and delete. The list comes from the vault, not the provider, so it doesn't know
 * whether an alias is on right now: both switches are offered, and repeating one changes nothing.
 */
function AliasActions({ alias, connected, busy, onSet, onDelete }: { alias: AliasRef; connected: boolean; busy: boolean; onSet: (enabled: boolean) => void; onDelete: () => void }) {
  if (!canManageAlias(alias.provider, alias.aliasId, alias.email)) return <small className={styles.aliasNote}>{t('maskedEmail.manageThere', { provider: providerName(alias.provider) })}</small>;
  if (!connected) return <small className={styles.aliasNote}>{t('maskedEmail.connectToManage', { provider: providerName(alias.provider) })}</small>;
  return (
    <div className={styles.aliasActions}>
      <Button variant="secondary" size="sm" disabled={busy} onClick={() => onSet(false)} aria-label={t('maskedEmail.turnOffAlias', { alias: alias.email })}>
        {t('maskedEmail.turnOff')}
      </Button>
      <Button variant="secondary" size="sm" disabled={busy} onClick={() => onSet(true)} aria-label={t('maskedEmail.turnOnAlias', { alias: alias.email })}>
        {t('maskedEmail.turnOn')}
      </Button>
      <Button variant="danger" size="sm" disabled={busy} onClick={onDelete} aria-label={t('maskedEmail.deleteAlias', { alias: alias.email })}>
        {t('maskedEmail.delete')}
      </Button>
    </div>
  );
}

/** The aliases logins use, from the recovery map: which logins use which alias. */
function AliasesSection() {
  const { report } = useHealth();
  const aliases = report?.recovery.filter((contact) => contact.aliasProvider) ?? [];
  const connections = useConnections();
  const { run, busy } = useAliasChange();
  const [deleting, setDeleting] = useState<RecoveryContact>();
  const reference = (contact: RecoveryContact): AliasRef => ({ provider: contact.aliasProvider!, aliasId: contact.aliasId ?? contact.value, email: contact.value });
  return (
    <Section title={t('maskedEmail.aliases')} description={t('maskedEmail.aliasesHelp')}>
      {report && aliases.length === 0 && <Row label={t('maskedEmail.noAliases')} />}
      {aliases.map((alias) => (
        <div key={alias.value} className={settings.row}>
          <div className={styles.alias}>
            <span className={styles.aliasHead}>
              <Icon name="mail" size={18} />
              <bdi dir="ltr" className={styles.aliasEmail}>
                {alias.value}
              </bdi>
              <small>
                {providerName(alias.aliasProvider!)} · {t('maskedEmail.usedBy', { count: alias.logins.length })}
              </small>
            </span>
            <ul className={styles.logins}>
              {alias.logins.map((login) => (
                <li key={login.itemId}>
                  <Link to={`/items/all/${login.itemId}`}>{login.title}</Link>
                </li>
              ))}
            </ul>
            <AliasActions
              alias={reference(alias)}
              connected={connections?.some((c) => c.provider === alias.aliasProvider) ?? false}
              busy={busy}
              onSet={(enabled) => void run((masked) => masked.setAliasEnabled(reference(alias), enabled), t(enabled ? 'maskedEmail.turnedOn' : 'maskedEmail.turnedOff'))}
              onDelete={() => setDeleting(alias)}
            />
          </div>
        </div>
      ))}
      <ConfirmDialog
        open={Boolean(deleting)}
        title={t('maskedEmail.deleteTitle')}
        confirmLabel={t('maskedEmail.delete')}
        onConfirm={async () => {
          const alias = deleting!;
          await run((masked) => masked.deleteAlias(reference(alias), alias.logins.map((login) => login.itemId)), t('maskedEmail.deleted'));
        }}
        onClose={() => setDeleting(undefined)}
      >
        <p>{t('maskedEmail.deleteBody', { alias: deleting?.value ?? '', provider: deleting ? providerName(deleting.aliasProvider!) : '' })}</p>
      </ConfirmDialog>
    </Section>
  );
}
