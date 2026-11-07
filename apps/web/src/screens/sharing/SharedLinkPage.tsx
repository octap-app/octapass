import { Avatar, Button, Icon } from '@octapass/ui';
import { isVaultError, type Item, type ShareLinkEnvelope, type SharedItem } from '@octapass/vault-client';
import { useMemo, useState, type FormEvent, type ReactNode } from 'react';
import { useLocation, useParams } from 'react-router';
import { DEFAULT_SERVER_URL } from '../../app/service';
import { useService } from '../../app/ServiceContext';
import { Alert } from '../../components/Alert';
import { PasswordInput } from '../../components/PasswordInput';
import { formatDate, t, type MessageKey } from '../../i18n';
import { errorMessage } from '../../lib/errors';
import { parseShareLink } from '../../lib/shareLinks';
import { AuthLayout } from '../auth/AuthLayout';
import { TypeFields } from '../vault/ItemDetail';
import styles from './SharedLinkPage.module.css';

/** The project website, where people without Octa Pass can read what it is (apps/website). */
const WEBSITE_URL = 'https://octap.app';

type State =
  | { step: 'intro' }
  | { step: 'passphrase'; envelope: ShareLinkEnvelope }
  | { step: 'item'; envelope: ShareLinkEnvelope; item: SharedItem }
  | { step: 'gone' }
  | { step: 'incomplete' };

/**
 * `/s/:linkId#<key>`: a share link, for anyone, signed in or not. Nothing is fetched until the
 * visitor asks, because fetching uses up a view; then the item is decrypted in this browser.
 */
export function SharedLinkPage() {
  const service = useService();
  const { linkId = '' } = useParams();
  const location = useLocation();
  const address = useMemo(() => parseShareLink(linkId, location.search, location.hash, DEFAULT_SERVER_URL), [linkId, location.search, location.hash]);
  const [state, setState] = useState<State>(() => (address.key && address.serverUrl ? { step: 'intro' } : { step: 'incomplete' }));
  const [passphrase, setPassphrase] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const sharing = service.sharing;
  const otherServer = address.serverUrl && new URL(address.serverUrl).origin !== new URL(DEFAULT_SERVER_URL).origin ? new URL(address.serverUrl).host : undefined;

  async function open(envelope: ShareLinkEnvelope, secret?: string) {
    try {
      const item = await sharing!.openShareLink(envelope.ciphertext, address.key, secret);
      setState({ step: 'item', envelope, item });
      setPassphrase('');
      // The key has done its job; keep it out of this tab's history from here on.
      window.history.replaceState(window.history.state, '', `${location.pathname}${location.search}`);
    } catch (e) {
      if (isVaultError(e, 'wrongPassphrase')) {
        setState({ step: 'passphrase', envelope });
        if (secret !== undefined) setError(errorMessage(e));
      } else if (isVaultError(e, 'invalidShareLink')) setState({ step: 'incomplete' });
      else setError(errorMessage(e));
    }
  }

  async function reveal() {
    if (!sharing) return;
    setBusy(true);
    setError(undefined);
    try {
      const envelope = await sharing.fetchShareLink(address.serverUrl, address.id);
      if (envelope.passphraseRequired) setState({ step: 'passphrase', envelope });
      else await open(envelope);
    } catch (e) {
      if (isVaultError(e, 'notFound')) setState({ step: 'gone' });
      else setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  async function unlock(event: FormEvent) {
    event.preventDefault();
    if (state.step !== 'passphrase' || !passphrase) return;
    setBusy(true);
    setError(undefined);
    await open(state.envelope, passphrase);
    setBusy(false);
  }

  const footer = (
    <span>
      {t('viewer.about')}{' '}
      <a href={WEBSITE_URL} rel="noopener noreferrer">
        {t('viewer.getOctaPass')}
      </a>
    </span>
  );

  switch (state.step) {
    case 'gone':
      return (
        <AuthLayout title={t('viewer.goneTitle')} subtitle={t('viewer.goneBody')} footer={footer} />
      );
    case 'incomplete':
      return (
        <AuthLayout title={t('viewer.incompleteTitle')} subtitle={t('viewer.incompleteBody')} footer={footer} />
      );
    case 'passphrase':
      return (
        <AuthLayout title={t('viewer.passphraseTitle')} subtitle={t('viewer.passphraseIntro')} footer={footer}>
          <form className={styles.form} onSubmit={unlock}>
            <PasswordInput label={t('viewer.passphrase')} autoComplete="off" autoFocus value={passphrase} onChange={(e) => setPassphrase(e.target.value)} error={error} />
            <Button type="submit" size="lg" block busy={busy} disabled={!passphrase}>
              {t('viewer.unlock')}
            </Button>
          </form>
        </AuthLayout>
      );
    case 'item':
      return <SharedItemView item={state.item} envelope={state.envelope} footer={footer} />;
    default:
      return (
        <AuthLayout title={t('viewer.title')} subtitle={t('viewer.intro')} footer={footer}>
          {otherServer && (
            <p className={styles.server}>
              <Icon name="server" size={16} />
              {t('viewer.server', { host: otherServer })}
            </p>
          )}
          {error && <Alert>{error}</Alert>}
          <Button size="lg" block icon="eye" busy={busy} onClick={() => void reveal()}>
            {t('viewer.open')}
          </Button>
          <p className={styles.note}>{t('viewer.useView')}</p>
        </AuthLayout>
      );
  }
}

function SharedItemView({ item, envelope, footer }: { item: SharedItem; envelope: ShareLinkEnvelope; footer: ReactNode }) {
  // The fields read an `Item`; a shared snapshot has no id, vault or history of its own.
  const asItem: Item = { id: 'shared', vaultId: 'shared', revision: 0, createdAt: envelope.expiresAt, updatedAt: envelope.expiresAt, overview: item.overview, details: item.details };
  const title = item.overview.title || t('detail.untitled');
  return (
    <AuthLayout
      wide
      title={
        <span className={styles.head}>
          <Avatar name={title} size="lg" />
          {title}
        </span>
      }
      subtitle={t(`types.${item.overview.type}` as MessageKey)}
      footer={footer}
    >
      <Alert tone="info">{t('viewer.readOnly')}</Alert>
      <div className={styles.fields}>
        <TypeFields item={asItem} />
      </div>
      <p className={styles.note}>{envelope.viewsLeft > 0 ? t('viewer.viewsLeft', { count: envelope.viewsLeft, date: formatDate(envelope.expiresAt, 'long') }) : t('viewer.lastView')}</p>
    </AuthLayout>
  );
}
