import { Icon, IconButton, Logo, Ring, type IconName } from '@octapass/ui';
import { isLocalServer, type ItemType, type Vault } from '@octapass/vault-client';
import { useState, type ReactNode } from 'react';
import { NavLink } from 'react-router';
import { useService, useSession } from '../../app/ServiceContext';
import { t, type MessageKey } from '../../i18n';
import { scoreTone, useHealth } from '../../lib/health';
import { useCounts, useVaults } from '../../lib/useItems';
import { useSharing } from '../../lib/useSharing';
import { CreateVaultDialog } from '../sharing/CreateVaultDialog';
import { vaultIcon } from '../sharing/SharingPage';
import styles from './Sidebar.module.css';

export const TYPE_ICONS: Record<ItemType, IconName> = {
  login: 'login',
  password: 'password',
  card: 'card',
  identity: 'identity',
  secureNote: 'note',
  document: 'document',
  wifi: 'wifi',
  environment: 'server',
  sshKey: 'key',
  apiCredential: 'key',
  certificate: 'shield',
  key: 'key',
  maskedEmailProvider: 'mail',
  healthSettings: 'shield',
  equivalentDomains: 'link',
  usageStats: 'history',
  bankAccount: 'card',
  softwareLicense: 'document',
  idDocument: 'identity',
  cryptoWallet: 'vault',
  database: 'server',
  custom: 'grid',
  customTemplate: 'grid',
};

const CATEGORIES: { scope: string; icon: IconName; label: MessageKey }[] = [
  { scope: 'login', icon: 'login', label: 'categories.login' },
  { scope: 'passkeys', icon: 'passkey', label: 'categories.passkeys' },
  { scope: 'codes', icon: 'clock', label: 'categories.codes' },
  { scope: 'card', icon: 'card', label: 'categories.card' },
  { scope: 'identity', icon: 'identity', label: 'categories.identity' },
  { scope: 'secureNote', icon: 'note', label: 'categories.secureNote' },
  { scope: 'password', icon: 'password', label: 'categories.password' },
  { scope: 'wifi', icon: 'wifi', label: 'categories.wifi' },
  { scope: 'environment', icon: 'server', label: 'categories.environment' },
  { scope: 'sshKey', icon: 'key', label: 'categories.sshKey' },
  { scope: 'certificate', icon: 'shield', label: 'categories.certificate' },
  { scope: 'key', icon: 'key', label: 'categories.key' },
  { scope: 'document', icon: 'document', label: 'categories.document' },
  { scope: 'bankAccount', icon: 'card', label: 'categories.bankAccount' },
  { scope: 'idDocument', icon: 'identity', label: 'categories.idDocument' },
  { scope: 'cryptoWallet', icon: 'vault', label: 'categories.cryptoWallet' },
  { scope: 'apiCredential', icon: 'key', label: 'categories.apiCredential' },
  { scope: 'database', icon: 'server', label: 'categories.database' },
  { scope: 'softwareLicense', icon: 'document', label: 'categories.softwareLicense' },
  { scope: 'custom', icon: 'grid', label: 'categories.custom' },
  { scope: 'customTemplate', icon: 'grid', label: 'categories.customTemplate' },
];

function vaultBadge(vault: Vault): string | undefined {
  if (vault.untrusted) return t('vault.untrusted');
  return vault.type === 'shared' ? t('vault.shared') : vault.type === 'family' ? t('vault.family') : undefined;
}

/**
 * The lists above the vaults, in this order. Nearby isn't built yet (it needs places saved with
 * items), so it shows as coming soon and goes nowhere.
 */
const QUICK_LISTS: { scope: string; icon: IconName; label: MessageKey; counted?: boolean; soon?: boolean }[] = [
  { scope: 'created', icon: 'sparkle', label: 'scopes.created' },
  { scope: 'nearby', icon: 'mapPin', label: 'scopes.nearby', soon: true },
  { scope: 'pinned', icon: 'pin', label: 'scopes.pinned', counted: true },
  { scope: 'favorites', icon: 'star', label: 'scopes.favorites', counted: true },
  { scope: 'frequent', icon: 'trending', label: 'scopes.frequent' },
  { scope: 'used', icon: 'history', label: 'scopes.used' },
  { scope: 'changed', icon: 'edit', label: 'scopes.changed' },
];

/** One link in the sidebar; hosts add their own (the extension's "This site") with it. */
export function SidebarRow({ to, icon, label, count, badge, warn }: { to: string; icon: IconName; label: string; count?: number; badge?: string; warn?: boolean }) {
  return (
    <li>
      <NavLink to={to} className={({ isActive }) => [styles.row, isActive && styles.on].filter(Boolean).join(' ')}>
        <Icon name={icon} size={18} />
        <span className={styles.label}>
          {label}
          {badge && <em className={warn ? styles.warn : undefined}>{badge}</em>}
        </span>
        {count !== undefined && <span className={styles.count}>{count}</span>}
      </NavLink>
    </li>
  );
}

/** A list that isn't built yet: shown, marked as coming soon, and not a link. */
function SoonRow({ icon, label }: { icon: IconName; label: string }) {
  return (
    <li>
      <span className={[styles.row, styles.soon].join(' ')} aria-disabled="true">
        <Icon name={icon} size={18} />
        <span className={styles.label}>
          {label}
          <em>{t('nav.soon')}</em>
        </span>
      </span>
    </li>
  );
}

/** `top`: links above the vaults; `bottom`: a card above the Health summary. Both are the host's (the extension's). */
export function Sidebar({ onLock, onClose, top, bottom }: { onLock: () => void; onClose: () => void; top?: ReactNode; bottom?: ReactNode }) {
  const session = useSession();
  const vaults = useVaults();
  const counts = useCounts();
  const { report } = useHealth();
  const sharing = useSharing();
  const service = useService();
  const local = isLocalServer(useSession().serverUrl);
  const canAttach = Boolean(service.attachments);
  const [creating, setCreating] = useState(false);

  return (
    <nav className={styles.sidebar} aria-label={t('nav.vault')}>
      <div className={styles.brand}>
        <Logo variant="tile" size={28} />
        <span className={styles.name}>
          Open<b>Pass</b>
        </span>
        <IconButton icon="lock" label={t('nav.lockNow')} onClick={onLock} size="sm" className={styles.lock} />
        <IconButton icon="close" label={t('common.close')} onClick={onClose} size="sm" className={styles.close} />
      </div>

      <div className={styles.scroll}>
        {top}
        <h2 className={styles.heading}>{t('nav.vaults')}</h2>
        <ul className={styles.list}>
          <SidebarRow to="/items/all" icon="grid" label={t('scopes.all')} count={counts?.all} />
          {QUICK_LISTS.map((list) =>
            list.soon ? (
              <SoonRow key={list.scope} icon={list.icon} label={t(list.label)} />
            ) : (
              <SidebarRow key={list.scope} to={`/items/${list.scope}`} icon={list.icon} label={t(list.label)} count={list.counted ? (counts?.[list.scope] ?? 0) : undefined} />
            ),
          )}
          {vaults?.map((vault) => (
            <SidebarRow key={vault.id} to={`/items/v-${vault.id}`} icon={vaultIcon(vault)} label={vault.name} badge={vaultBadge(vault)} warn={vault.untrusted} count={counts?.[`v-${vault.id}`] ?? 0} />
          ))}
          {sharing && (
            <li>
              <button type="button" className={[styles.row, styles.add].join(' ')} onClick={() => setCreating(true)}>
                <Icon name="plus" size={18} />
                <span className={styles.label}>{t('nav.newSharedVault')}</span>
              </button>
            </li>
          )}
        </ul>

        <h2 className={styles.heading}>{t('nav.categories')}</h2>
        <ul className={styles.list}>
          {/* Documents need file storage: shown where it exists, or when documents arrived from elsewhere. */}
          {CATEGORIES.filter((c) => c.scope !== 'document' || canAttach || counts?.document).map((c) => (
            <SidebarRow key={c.scope} to={`/items/${c.scope}`} icon={c.icon} label={t(c.label)} count={counts?.[c.scope] ?? 0} />
          ))}
        </ul>

        <h2 className={styles.heading}>{t('nav.tools')}</h2>
        <ul className={styles.list}>
          <SidebarRow to="/generator" icon="wand" label={t('nav.generator')} />
          {service.files && <SidebarRow to="/files" icon="lock" label={t('nav.files')} />}
          {service.toolkit && <SidebarRow to="/tools" icon="code" label={t('nav.devTools')} />}
          {service.maskedEmail && <SidebarRow to="/masked-email" icon="mail" label={t('nav.maskedEmail')} />}
          {/* A local vault shows these too, each with its "Needs sync" note (plan 05). */}
          {(sharing || local) && (
            <>
              <SidebarRow to="/sharing" icon="share" label={t('nav.sharing')} />
              {service.organisations && <SidebarRow to="/organisation" icon="users" label={t('nav.organisation')} />}
              <SidebarRow to="/emergency" icon="lifebuoy" label={t('nav.emergency')} />
            </>
          )}
          <SidebarRow to="/items/trash" icon="trash" label={t('scopes.trash')} count={counts?.trash} />
          <SidebarRow to="/settings" icon="settings" label={t('nav.settings')} />
        </ul>
      </div>

      {bottom}
      <NavLink to="/health" className={({ isActive }) => [styles.health, isActive && styles.healthOn].filter(Boolean).join(' ')}>
        <Ring value={(report?.score ?? 0) / 100} size={38} stroke={4} tone={report ? scoreTone(report.score) : 'free'} />
        <span className={styles.healthText}>
          <b>{report ? report.score : '–'}</b>
          <span>{t('nav.health')}</span>
        </span>
        <Icon name="chevronRight" size={16} className={styles.chev} />
      </NavLink>
      <p className={styles.account} title={session.email}>
        <bdi dir="ltr">{session.email}</bdi>
      </p>
      <CreateVaultDialog open={creating} onClose={() => setCreating(false)} />
    </nav>
  );
}
