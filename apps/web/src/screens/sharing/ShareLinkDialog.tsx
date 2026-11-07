import { Button, Dialog, Icon, Select, TextField } from '@octapass/ui';
import type { CreatedShareLink, Item } from '@octapass/vault-client';
import { useEffect, useState, type FormEvent } from 'react';
import { Link } from 'react-router';
import { DEFAULT_SERVER_URL } from '../../app/service';
import { useSession } from '../../app/ServiceContext';
import { Alert } from '../../components/Alert';
import { PasswordInput } from '../../components/PasswordInput';
import { formatDate, t } from '../../i18n';
import { useCopy } from '../../lib/clipboard';
import { errorMessage } from '../../lib/errors';
import { shareLinkUrl } from '../../lib/shareLinks';
import { useSharing } from '../../lib/useSharing';
import styles from './Dialogs.module.css';

const EXPIRY_HOURS = [1, 24, 72, 168, 720];

const expiryLabel = (hours: number) => (hours < 24 ? t('shareLink.hours', { count: hours }) : t('shareLink.days', { count: hours / 24 }));

/** Item → Share a copy: a one-time link to a snapshot, with an expiry, a view limit and an optional passphrase. */
export function ShareLinkDialog({ item, open, onClose }: { item: Item; open: boolean; onClose: () => void }) {
  const sharing = useSharing();
  const session = useSession();
  const copy = useCopy();
  const [hours, setHours] = useState(24);
  const [views, setViews] = useState('1');
  const [passphrase, setPassphrase] = useState('');
  const [created, setCreated] = useState<{ link: CreatedShareLink; url: string; passphrase: boolean }>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const maxViews = Number(views);
  const viewsValid = Number.isInteger(maxViews) && maxViews >= 1 && maxViews <= 100;

  useEffect(() => {
    if (!open) return;
    setHours(24);
    setViews('1');
    setPassphrase('');
    setCreated(undefined);
    setError(undefined);
  }, [open]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!sharing || !viewsValid) return;
    setBusy(true);
    setError(undefined);
    try {
      const link = await sharing.createShareLink(item.id, { expiresInHours: hours, maxViews, passphrase: passphrase || undefined });
      // The apps' pages aren't on the web vault's origin, so they make the address themselves.
      const url = link.url ?? shareLinkUrl(window.location.origin, link, session.serverUrl ?? DEFAULT_SERVER_URL, DEFAULT_SERVER_URL);
      setCreated({ link, url, passphrase: Boolean(passphrase) });
      setPassphrase('');
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  const title = t('shareLink.title', { title: item.overview.title || t('detail.untitled') });
  return (
    <Dialog open={open} onClose={busy ? () => undefined : onClose} closeLabel={t('common.close')} title={created ? t('shareLink.ready') : title} size="md">
      {created ? (
        <div className={styles.form}>
          <p className={styles.intro}>{t('shareLink.readyBody', { date: formatDate(created.link.expiresAt, 'long') })}</p>
          <div className={styles.link}>
            <TextField label={t('shareLink.link')} readOnly mono value={created.url} onFocus={(e) => e.currentTarget.select()} />
            <div>
              <Button size="sm" icon="copy" onClick={() => void copy(created.url, t('shareLink.linkWhat'))}>
                {t('shareLink.copyLink')}
              </Button>
            </div>
          </div>
          {created.passphrase && <Alert tone="info">{t('shareLink.sendPassphrase')}</Alert>}
          <div className={styles.footer}>
            <Link to="/sharing#links" className={styles.intro} onClick={onClose}>
              {t('shareLink.manage')}
            </Link>
            <Button onClick={onClose}>{t('common.done')}</Button>
          </div>
        </div>
      ) : (
        <form className={styles.form} onSubmit={submit} noValidate>
          <p className={styles.secure}>
            <Icon name="lock" size={16} />
            <span>{t('shareLink.intro')}</span>
          </p>
          <div className={styles.fields}>
            <Select label={t('shareLink.expires')} options={EXPIRY_HOURS.map((h) => ({ value: String(h), label: expiryLabel(h) }))} value={String(hours)} onChange={(e) => setHours(Number(e.target.value))} />
            <TextField
              label={t('shareLink.views')}
              type="number"
              inputMode="numeric"
              min={1}
              max={100}
              value={views}
              onChange={(e) => setViews(e.target.value)}
              hint={t('shareLink.viewsHint')}
              error={views !== '' && !viewsValid ? t('shareLink.viewsHint') : undefined}
            />
          </div>
          <PasswordInput label={t('shareLink.passphrase')} autoComplete="off" value={passphrase} onChange={(e) => setPassphrase(e.target.value)} hint={t('shareLink.passphraseHint')} />
          {error && <Alert>{error}</Alert>}
          <div className={styles.footer}>
            <Button variant="secondary" disabled={busy} onClick={onClose}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" icon="link" busy={busy} disabled={!viewsValid}>
              {t('shareLink.create')}
            </Button>
          </div>
        </form>
      )}
    </Dialog>
  );
}
