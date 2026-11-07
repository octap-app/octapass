import { Avatar, Button, Icon, Spinner } from '@octapass/ui';
import { Alert } from '@octapass/web/src/components/Alert';
import { errorMessage } from '@octapass/web/src/lib/errors';
import { useEffect, useState } from 'react';
import { useParams } from 'react-router';
import type { HttpAuthPrompt as Prompt } from '../background/httpAuth';
import { tx } from '../i18n';
import { Frame } from '../passkey/Prompt';
import styles from '../passkey/Prompt.module.css';
import { useExtension } from './ExtensionContext';

/**
 * The window the background opens the first time a site's HTTP sign-in prompt matches a login. The
 * title names the origin the browser reports; the realm comes from the site, so it's only shown
 * as the site's own words. Picking a login allows the site from then on (Settings can take it back).
 */
export function HttpAuthPrompt() {
  const { api } = useExtension();
  const { id = '' } = useParams();
  const [prompt, setPrompt] = useState<Prompt | 'ended'>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();

  useEffect(() => {
    api.httpAuthPrompt(id).then(setPrompt, () => setPrompt('ended'));
  }, [api, id]);

  async function approve(itemId: string) {
    setBusy(true);
    setError(undefined);
    try {
      await api.httpAuthApprove(id, itemId);
      window.close();
    } catch (e) {
      setError(errorMessage(e));
      setBusy(false);
    }
  }

  async function decline() {
    await api.httpAuthDecline(id).catch(() => {});
    window.close();
  }

  if (!prompt) return <Frame><Spinner size={22} /></Frame>;
  if (prompt === 'ended') return <Frame title={tx('httpAuth.ended')} />;

  const { host, protocol } = new URL(prompt.origin);
  return (
    <Frame title={tx('httpAuth.title', { host })}>
      {error && <Alert>{error}</Alert>}
      <p className={styles.body}>
        {prompt.realm ? tx('httpAuth.bodyRealm', { realm: prompt.realm }) : tx('httpAuth.body')}
        {protocol === 'http:' && ` ${tx('httpAuth.notSecure')}`}
      </p>
      <ul className={styles.matches} aria-label={tx('httpAuth.choose')}>
        {prompt.logins.map((login) => (
          <li key={login.itemId}>
            <button type="button" className={styles.match} disabled={busy} onClick={() => void approve(login.itemId)}>
              <Avatar name={login.title} />
              <span>
                <strong>{login.title}</strong>
                <small>{login.username}</small>
              </span>
              <Icon name="key" size={18} />
            </button>
          </li>
        ))}
      </ul>
      <Button variant="ghost" block disabled={busy} onClick={() => void decline()}>
        {tx('httpAuth.notNow')}
      </Button>
    </Frame>
  );
}
