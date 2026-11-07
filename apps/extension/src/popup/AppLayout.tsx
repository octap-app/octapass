import { SidebarRow } from '@octapass/web/src/screens/vault/Sidebar';
import sidebarStyles from '@octapass/web/src/screens/vault/Sidebar.module.css';
import { VaultLayout } from '@octapass/web/src/screens/vault/VaultLayout';
import { tx } from '../i18n';
import { GetApps } from './GetApps';

/**
 * The app tab: the web vault's layout, with "This site" first in the sidebar and an offer of the
 * other Octa Pass apps at its foot. The service worker owns the lock timers, so the page runs none.
 */
export function AppLayout() {
  return (
    <VaultLayout
      lockTimers={false}
      sidebarTop={
        <ul className={sidebarStyles.list}>
          <SidebarRow to="/items/site" icon="login" label={tx('view.thisSite')} />
        </ul>
      }
      sidebarBottom={<GetApps />}
    />
  );
}
