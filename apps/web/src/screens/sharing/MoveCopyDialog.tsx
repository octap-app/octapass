import { Button, Dialog, Icon, useToast } from '@octapass/ui';
import type { Item } from '@octapass/vault-client';
import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router';
import { Alert } from '../../components/Alert';
import { t } from '../../i18n';
import { errorMessage } from '../../lib/errors';
import { useVaults } from '../../lib/useItems';
import { useSharing } from '../../lib/useSharing';
import { vaultIcon } from './SharingPage';
import styles from './Dialogs.module.css';

/** Item → Move to… / Copy to…: any other vault the user can add items to. */
export function MoveCopyDialog({ item, mode, onClose }: { item: Item; mode: 'move' | 'copy' | undefined; onClose: () => void }) {
  const sharing = useSharing();
  const navigate = useNavigate();
  const toast = useToast();
  const targets = (useVaults() ?? []).filter((v) => v.id !== item.vaultId && v.role !== 'read' && !v.untrusted);
  const [target, setTarget] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();

  useEffect(() => {
    if (!mode) return;
    setTarget(undefined);
    setError(undefined);
  }, [mode]);

  const chosen = targets.find((v) => v.id === (target ?? targets[0]?.id));
  const title = item.overview.title || t('detail.untitled');

  async function submit() {
    if (!sharing || !chosen || !mode) return;
    setBusy(true);
    setError(undefined);
    try {
      const result = mode === 'move' ? await sharing.moveItem(item.id, chosen.id) : await sharing.copyItem(item.id, chosen.id);
      toast({ message: t(mode === 'move' ? 'moveCopy.moved' : 'moveCopy.copied', { vault: chosen.name }), tone: 'success' });
      onClose();
      navigate(`/items/v-${chosen.id}/${result.id}`);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog
      open={mode !== undefined}
      onClose={busy ? () => undefined : onClose}
      closeLabel={t('common.close')}
      title={t(mode === 'copy' ? 'moveCopy.copyTitle' : 'moveCopy.moveTitle', { title })}
      description={t(mode === 'copy' ? 'moveCopy.copyIntro' : 'moveCopy.moveIntro')}
      footer={
        <>
          <Button variant="secondary" disabled={busy} onClick={onClose}>
            {t('common.cancel')}
          </Button>
          <Button icon={mode === 'copy' ? 'copy' : 'move'} busy={busy} disabled={!chosen} onClick={() => void submit()}>
            {t(mode === 'copy' ? 'moveCopy.copyAction' : 'moveCopy.moveAction')}
          </Button>
        </>
      }
    >
      {targets.length === 0 ? (
        <p className={styles.intro}>{t('moveCopy.noTargets')}</p>
      ) : (
        <fieldset className={styles.choices}>
          <legend className="visually-hidden">{t('moveCopy.vault')}</legend>
          {targets.map((vault) => (
            <label key={vault.id} className={styles.choice}>
              <input type="radio" name="target-vault" value={vault.id} checked={chosen?.id === vault.id} onChange={() => setTarget(vault.id)} />
              <Icon name={vaultIcon(vault)} size={18} />
              <span>{vault.name}</span>
            </label>
          ))}
        </fieldset>
      )}
      {error && <Alert>{error}</Alert>}
    </Dialog>
  );
}
