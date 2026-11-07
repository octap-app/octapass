import { Avatar, Icon } from '@octapass/ui';
import { hostnameOf, type ItemSummary } from '@octapass/vault-client';
import { useId, useState } from 'react';
import { t } from '../../../i18n';
import { useItems, useVaults } from '../../../lib/useItems';
import styles from './otp.module.css';

const SHOWN = 8;

/** The logins a one-time code can join: in vaults the user can change. */
export function useLogins(): ItemSummary[] | undefined {
  const { items } = useItems({});
  const vaults = useVaults();
  if (!items || !vaults) return undefined;
  const writable = new Set(vaults.filter((v) => v.role !== 'read' && !v.untrusted).map((v) => v.id));
  return items.filter((item) => (item.type === 'login' || item.type === 'password') && writable.has(item.vaultId));
}

/** Matches title, username and website, each word anywhere. */
export function matchesLogin(item: ItemSummary, query: string): boolean {
  const haystack = [item.title, item.subtitle, ...(item.urls ?? []).map((url) => hostnameOf(url) ?? url)].join(' ').toLowerCase();
  return query
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean)
    .every((word) => haystack.includes(word));
}

export interface LoginPickerProps {
  logins: ItemSummary[];
  /** The chosen login, or `undefined` for "keep as a separate item". */
  value: string | undefined;
  onChange: (loginId: string | undefined) => void;
  /** Logins another code already goes to. */
  taken?: ReadonlySet<string>;
  /** Offers "Keep as a separate item". */
  allowSeparate?: boolean;
  /** Logins that can't be picked (the item itself). */
  exclude?: string;
  label: string;
}

/** Searchable list of logins; logins that already have a code can't be picked. */
export function LoginPicker({ logins, value, onChange, taken, allowSeparate = true, exclude, label }: LoginPickerProps) {
  const [query, setQuery] = useState('');
  const searchId = useId();
  const name = useId();
  const candidates = logins.filter((login) => login.id !== exclude && (!query.trim() || matchesLogin(login, query.trim())));
  // The chosen login stays in the list even when the search would hide it.
  const chosen = logins.find((login) => login.id === value);
  const shown = candidates.slice(0, SHOWN);
  if (chosen && !shown.includes(chosen)) shown.unshift(chosen);

  return (
    <div className={styles.picker}>
      <div className={styles.search}>
        <Icon name="search" size={16} />
        <input id={searchId} type="search" aria-label={label} placeholder={t('otp.searchLogins')} value={query} onChange={(event) => setQuery(event.target.value)} />
      </div>
      <fieldset className={styles.options}>
        <legend className="visually-hidden">{label}</legend>
        {allowSeparate && (
          <label className={styles.option}>
            <input type="radio" name={name} checked={value === undefined} onChange={() => onChange(undefined)} />
            <Icon name="plus" size={18} />
            <span className={styles.optionText}>
              <strong>{t('otp.separate')}</strong>
            </span>
          </label>
        )}
        {shown.map((login) => {
          const unavailable = login.id !== value && (login.hasTotp || taken?.has(login.id));
          return (
            <label key={login.id} className={styles.option} data-disabled={unavailable || undefined}>
              <input type="radio" name={name} checked={value === login.id} disabled={unavailable} onChange={() => onChange(login.id)} />
              <Avatar name={login.title} size="sm" />
              <span className={styles.optionText}>
                <strong>
                  <bdi>{login.title || t('detail.untitled')}</bdi>
                </strong>
                <small>
                  {unavailable ? (
                    login.hasTotp ? t('otp.hasCode') : t('otp.takenByOther')
                  ) : (
                    <bdi>{[login.subtitle, login.urls?.[0] && (hostnameOf(login.urls[0]) ?? login.urls[0])].filter(Boolean).join(' · ')}</bdi>
                  )}
                </small>
              </span>
            </label>
          );
        })}
        {candidates.length === 0 && <p className={styles.empty}>{t('otp.noLogins')}</p>}
        {candidates.length > SHOWN && <p className={styles.empty}>{t('otp.moreLogins', { count: candidates.length - SHOWN })}</p>}
      </fieldset>
    </div>
  );
}
