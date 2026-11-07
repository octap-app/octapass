import { IconButton } from '@octapass/ui';
import { useService, useSession } from '@octapass/web/src/app/ServiceContext';
import { t } from '@octapass/web/src/i18n';
import { ItemAvatar } from '@octapass/web/src/lib/siteIcons';
import { useItems } from '@octapass/web/src/lib/useItems';
import { GeneratorPage } from '@octapass/web/src/screens/generator/GeneratorPage';
import type { LayoutContext } from '@octapass/web/src/screens/vault/VaultLayout';
import pageStyles from '@octapass/web/src/screens/vault/ItemsPage.module.css';
import { Outlet, useMatch, useNavigate, useOutletContext } from 'react-router';
import { webPage } from '../background/matching';
import { tx } from '../i18n';
import { LOCAL_SERVER } from '../shared/local';
import { BrowserAutofillOffer } from './BrowserAutofill';
import { SiteItems } from './ItemList';
import { BackupReminder } from './local/BackupReminder';
import { useCurrentTab } from './useCurrentTab';
import styles from './SitePage.module.css';

/**
 * "This site": the logins for the page the user was on, with Fill, beside the item they open. Laid
 * out like the vault's other lists.
 */
export function SitePage() {
  const service = useService();
  const session = useSession();
  const navigate = useNavigate();
  const { openDrawer } = useOutletContext<LayoutContext>();
  const tab = useCurrentTab();
  const page = tab?.url ? webPage(tab.url) : undefined;
  const showingList = useMatch('/items/site') !== null;

  return (
    <div className={pageStyles.page} data-view={showingList ? 'list' : 'detail'}>
      <section className={pageStyles.listPane} aria-labelledby="list-title">
        <header className={pageStyles.header}>
          <div className={pageStyles.titleRow}>
            <IconButton icon="menu" label={t('nav.openMenu')} className={pageStyles.menuButton} onClick={openDrawer} />
            <h1 id="list-title" className={pageStyles.title}>
              {tx('view.thisSite')}
            </h1>
            {service.qrCapture && <IconButton icon="qrCode" label={t('otp.source.page')} onClick={() => navigate('/scan')} />}
          </div>
          {page ? (
            <p className={styles.page}>
              <ItemAvatar name={page.hostname} urls={[page.origin]} />
              <span className={styles.pageText}>
                <bdi className={styles.host}>{page.hostname}</bdi>
                <span className={styles.hint}>{tx('view.thisSiteFor')}</span>
              </span>
            </p>
          ) : null}
        </header>
        <BrowserAutofillOffer />
        {session.serverUrl === LOCAL_SERVER && <LocalReminder />}
        <div className={pageStyles.listScroll}>
          <SiteItems tab={tab} />
        </div>
      </section>
      <section className={pageStyles.detailPane} aria-label={t('detail.region')}>
        <Outlet />
      </section>
    </div>
  );
}

function LocalReminder() {
  const { items } = useItems({});
  return <BackupReminder itemCount={items?.length ?? 0} />;
}

/** The vault's Generator, with a masked email for the page the user was on. */
export function SiteGenerator() {
  const url = useCurrentTab()?.url;
  return <GeneratorPage site={url && webPage(url) ? url : ''} />;
}
