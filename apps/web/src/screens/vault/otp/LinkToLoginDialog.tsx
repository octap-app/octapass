import { Button, Dialog, Spinner, useToast } from '@octapass/ui';
import type { Item, LoginDetails } from '@octapass/vault-client';
import { useState } from 'react';
import { useNavigate, useParams } from 'react-router';
import { useService } from '../../../app/ServiceContext';
import { Alert } from '../../../components/Alert';
import { t } from '../../../i18n';
import { errorMessage } from '../../../lib/errors';
import { LoginPicker, useLogins } from './LoginPicker';

/**
 * A one-time code on an item of its own → Link to a login: the code (its `otpauth://` link, with
 * issuer, period, digits and algorithm) moves into the chosen login, and this item goes to the
 * trash, where it can still be restored.
 */
export function LinkToLoginDialog({ item, open, onClose }: { item: Item; open: boolean; onClose: () => void }) {
  return open ? <LinkToLogin item={item} onClose={onClose} /> : null;
}

function LinkToLogin({ item, onClose }: { item: Item; onClose: () => void }) {
  const service = useService();
  const toast = useToast();
  const navigate = useNavigate();
  const { scope = 'all' } = useParams();
  const logins = useLogins();
  const [target, setTarget] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();

  async function link() {
    if (!target) return;
    setBusy(true);
    setError(undefined);
    try {
      const login = await service.getItem(target);
      const totp = (item.details as LoginDetails).totp!;
      await service.saveItem({ ...login, details: { ...(login.details as LoginDetails), totp } });
      await service.deleteItem(item.id);
      toast({ message: t('otp.linked', { title: login.overview.title }), tone: 'success', duration: 5000 });
      onClose();
      navigate(`/items/${scope}/${login.id}`);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog
      open
      size="md"
      onClose={busy ? () => undefined : onClose}
      closeLabel={t('common.close')}
      title={t('otp.linkTitle')}
      description={t('otp.linkHelp')}
      footer={
        <>
          <Button variant="secondary" disabled={busy} onClick={onClose}>
            {t('common.cancel')}
          </Button>
          <Button icon="link" busy={busy} disabled={!target} onClick={() => void link()}>
            {t('otp.linkAction')}
          </Button>
        </>
      }
    >
      {logins ? (
        <LoginPicker logins={logins} value={target} onChange={setTarget} allowSeparate={false} exclude={item.id} label={t('otp.linkPicker')} />
      ) : (
        <Spinner size={20} />
      )}
      {error && <Alert>{error}</Alert>}
    </Dialog>
  );
}
