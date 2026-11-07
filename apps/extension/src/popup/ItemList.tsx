import { Button, EmptyState, Icon, IconButton, Spinner, useToast } from '@octapass/ui';
import { authorizedKeysLine, loginDetails, type ItemSummary, type SshKeyDetails } from '@octapass/vault-client';
import { useService } from '@octapass/web/src/app/ServiceContext';
import { t } from '@octapass/web/src/i18n';
import { useCopy } from '@octapass/web/src/lib/clipboard';
import { errorMessage } from '@octapass/web/src/lib/errors';
import { ItemAvatar } from '@octapass/web/src/lib/siteIcons';
import { useEffect, useState } from 'react';
import { useMatch, useNavigate } from 'react-router';
import { webPage, type OtherPartLogin } from '../background/matching';
import type { WebsiteAnswer, WebsitePrompt } from '../shared/messages';
import { tx } from '../i18n';
import { useExtension } from './ExtensionContext';
import { showTab, type CurrentTab } from './useCurrentTab';
import styles from './ItemList.module.css';

/**
 * Logins for the page in the current tab, with a Fill button, best match first. Logins for other parts
 * of the page's site come after, folded away under "Logins for other parts of example.com".
 */
export function SiteItems({ tab }: { tab: CurrentTab | undefined }) {
  const site = tab?.url ? webPage(tab.url) : undefined;
  const found = useSiteItems(site && tab?.url);
  if (!tab) return <Loading />;
  if (!site) return <EmptyState icon="login" title={tx('site.unsupported')}>{tx('site.none')}</EmptyState>;
  if (!found) return <Loading />;
  const { items, others } = found;
  return (
    <>
      {items.length ? (
        <ul className={styles.list} aria-label={site.hostname}>
          {items.map((item) => (
            <Row key={item.id} item={item} scope="site" tab={tab} />
          ))}
        </ul>
      ) : (
        <EmptyState icon="search" title={tx('site.noLogins', { host: site.hostname })}>
          {tx('site.noLoginsBody')}
        </EmptyState>
      )}
      {others.length > 0 && <OtherLogins others={others} tab={tab} />}
    </>
  );
}

/** Quiet and closed: these aren't for the page, so they're one tap away rather than offered. */
function OtherLogins({ others, tab }: { others: OtherPartLogin[]; tab: CurrentTab }) {
  const label = tx('site.otherLogins', { site: others[0]!.site });
  return (
    <details className={styles.others}>
      <summary>{label}</summary>
      <ul className={styles.list} aria-label={label}>
        {others.map(({ item, host }) => (
          <Row key={item.id} item={item} scope="site" tab={tab} otherHost={host} />
        ))}
      </ul>
    </details>
  );
}

interface SiteLogins {
  url: string;
  items: ItemSummary[];
  others: OtherPartLogin[];
}

function useSiteItems(url: string | undefined): SiteLogins | undefined {
  const service = useService();
  const { api } = useExtension();
  const [found, setFound] = useState<SiteLogins>();
  useEffect(() => {
    if (!url) return;
    let live = true;
    const load = () =>
      void Promise.all([api.siteItems(url), api.siteOtherLogins(url)]).then(([items, others]) => live && setFound({ url, items, others }));
    load();
    const unsubscribe = service.onItemsChange(load);
    return () => {
      live = false;
      unsubscribe();
    };
  }, [api, service, url]);
  return found && found.url === url ? found : undefined;
}

/** `otherHost`: a login for another part of the page's site, saved for this host. */
function Row({ item, scope, tab, otherHost }: { item: ItemSummary; scope: string; tab?: CurrentTab; otherHost?: string }) {
  const navigate = useNavigate();
  const service = useService();
  const { api } = useExtension();
  const copy = useCopy();
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const [offer, setOffer] = useState<WebsitePrompt>();
  const login = item.type === 'login' || item.type === 'password';

  // Back to the page, which now holds the login.
  const done = () => {
    toast({ message: tx('site.filled', { title: item.title }), tone: 'success' });
    if (tab) void showTab(tab.id).catch(() => undefined);
  };

  async function fill() {
    setBusy(true);
    try {
      if (otherHost) {
        // Checked again in the service worker: only a login for another part of this page's site.
        const filled = await api.fillOtherLogin(tab!.id, item.id);
        if (!filled) toast({ message: tx('site.fillFailed'), tone: 'danger' });
        else if (filled.offer) setOffer(filled.offer);
        else done();
        return;
      }
      const filled = await api.fillTab(tab!.id, item.id);
      if (!filled) toast({ message: tx('site.fillFailed'), tone: 'danger' });
      else done();
    } catch (e) {
      toast({ message: errorMessage(e), tone: 'danger' });
    } finally {
      setBusy(false);
    }
  }

  async function answer(choice: WebsiteAnswer) {
    const current = offer!;
    setOffer(undefined);
    const added = await api.answerWebsite(tab!.id, current.id, choice).catch(() => false);
    if (choice === 'add' && !added) {
      toast({ message: tx('site.websiteNotAdded', { host: current.host }), tone: 'danger' });
      return;
    }
    if (choice === 'add') toast({ message: tx('site.websiteAdded', { host: current.host, title: current.title }), tone: 'success' });
    if (tab) void showTab(tab.id).catch(() => undefined);
  }

  async function copyPublicKey() {
    const line = authorizedKeysLine((await service.getItem(item.id)).details as SshKeyDetails);
    if (line) {
      await copy(line, t('sshKey.publicKey'), { secret: false });
      void api.recordItemUse(item.id).catch(() => undefined);
    }
  }

  async function copyPassword() {
    const password = loginDetails(await service.getItem(item.id))?.password;
    if (password) {
      await copy(password, t('fields.password'));
      void api.recordItemUse(item.id).catch(() => undefined);
    }
  }

  const open = useMatch(`/items/${scope}/${item.id}/*`) !== null;
  const row = (
    <li className={styles.row} data-on={open || undefined}>
      <button type="button" className={styles.open} aria-current={open ? 'page' : undefined} onClick={() => navigate(`/items/${scope}/${item.id}`)}>
        <ItemAvatar name={item.title} urls={item.urls} />
        <span className={styles.text}>
          <span className={styles.title}>
            <bdi>{item.title || t('detail.untitled')}</bdi>
          </span>
          {otherHost ? (
            <span className={styles.sub}>
              <bdi>{otherHost}</bdi>
              {item.subtitle && (
                <>
                  {' · '}
                  <bdi>{item.subtitle}</bdi>
                </>
              )}
            </span>
          ) : (
            item.subtitle && (
              <span className={styles.sub}>
                <bdi>{item.subtitle}</bdi>
              </span>
            )
          )}
        </span>
        {item.hasPasskey && <Icon name="passkey" size={15} label={t('list.hasPasskey')} />}
      </button>
      {login && <IconButton icon="copy" size="sm" label={t('copy.action', { what: t('fields.password') })} onClick={() => void copyPassword()} />}
      {item.type === 'sshKey' && <IconButton icon="copy" size="sm" label={t('copy.action', { what: t('sshKey.publicKey') })} onClick={() => void copyPublicKey()} />}
      {tab && login && (
        <Button size="sm" busy={busy} onClick={() => void fill()} aria-label={tx('site.fillWhat', { title: item.title })}>
          {tx('site.fill')}
        </Button>
      )}
    </li>
  );
  if (!offer) return row;
  return (
    <>
      {row}
      <li className={styles.offer} role="group" aria-label={tx('site.addWebsite', { host: offer.host })}>
        <p>{tx('site.addWebsite', { host: offer.host })}</p>
        <div className={styles.offerActions}>
          <Button size="sm" variant="secondary" onClick={() => void answer('notNow')}>
            {tx('site.notNow')}
          </Button>
          <Button size="sm" onClick={() => void answer('add')}>
            {tx('site.add')}
          </Button>
        </div>
      </li>
    </>
  );
}

function Loading() {
  return (
    <div className={styles.loading} aria-busy="true" aria-label={t('common.loading')}>
      <Spinner size={22} />
    </div>
  );
}
