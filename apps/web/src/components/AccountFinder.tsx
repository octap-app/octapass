import { Avatar, Button, Checkbox, KeyFingerprint, TextField } from '@octapass/ui';
import type { AccountLookup } from '@octapass/vault-client';
import { useState, type FormEvent, type ReactNode } from 'react';
import { t } from '../i18n';
import { errorMessage } from '../lib/errors';
import { useSharing } from '../lib/useSharing';
import { Alert } from './Alert';
import { KeyLogNote } from './KeyLogNote';
import styles from './AccountFinder.module.css';

export interface AccountFinderProps {
  submitLabel: string;
  /** Asked once the account is found, before submitting: a role, a waiting period… */
  options?: ReactNode;
  /** Shares with the account. Rejecting shows the error and keeps the form as it is. */
  onSubmit: (account: AccountLookup) => Promise<void>;
  disabled?: boolean;
  /** Who to look for, when it's already known. */
  initialEmail?: string;
}

/**
 * Finds an Octa Pass account by email and shows its fingerprint to compare out of band before
 * anything is shared with it. Ticking "it matches" remembers the fingerprint on this device.
 */
export function AccountFinder({ submitLabel, options, onSubmit, disabled, initialEmail = '' }: AccountFinderProps) {
  const sharing = useSharing()!;
  const [email, setEmail] = useState(initialEmail);
  const [account, setAccount] = useState<AccountLookup>();
  const [matches, setMatches] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();

  async function run(action: () => Promise<void>) {
    setBusy(true);
    setError(undefined);
    try {
      await action();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  function find(event: FormEvent) {
    event.preventDefault();
    if (!email.trim()) return;
    void run(async () => {
      setAccount(await sharing.lookupAccount(email));
      setMatches(false);
    });
  }

  function submit(event: FormEvent) {
    event.preventDefault();
    if (!account) return;
    void run(async () => {
      if (matches) await sharing.markVerified(account);
      await onSubmit(account);
      setAccount(undefined);
      setEmail('');
    });
  }

  if (!account) {
    return (
      <form className={styles.find} onSubmit={find} noValidate>
        <TextField
          label={t('people.email')}
          type="email"
          autoComplete="off"
          spellCheck={false}
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          error={error}
          disabled={disabled}
        />
        <Button type="submit" variant="secondary" icon="search" busy={busy} disabled={disabled || !email.trim()}>
          {t('people.find')}
        </Button>
      </form>
    );
  }

  return (
    <form className={styles.found} onSubmit={submit}>
      <div className={styles.person}>
        <Avatar name={account.email} size="md" />
        <div className={styles.personText}>
          <strong>{account.email}</strong>
          <span>{t('people.found')}</span>
        </div>
        <Button variant="ghost" size="sm" onClick={() => setAccount(undefined)} disabled={busy}>
          {t('people.change')}
        </Button>
      </div>
      <div className={styles.compare}>
        <KeyFingerprint
          label={t('fingerprint.title')}
          emojiLabel={t('fingerprint.emoji')}
          digits={account.fingerprint.digits}
          emoji={account.fingerprint.emoji}
        />
        <p>{t('fingerprint.compareHelp', { email: account.email })}</p>
        <KeyLogNote check={account.keyLog} />
      </div>
      <Checkbox label={t('fingerprint.matches', { email: account.email })} checked={matches} onChange={(e) => setMatches(e.target.checked)} />
      {options}
      {error && <Alert>{error}</Alert>}
      <div>
        <Button type="submit" icon="userPlus" busy={busy} disabled={disabled || account.keyLog === 'failed'}>
          {submitLabel}
        </Button>
      </div>
    </form>
  );
}
