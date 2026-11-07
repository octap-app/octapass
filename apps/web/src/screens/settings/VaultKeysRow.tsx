import { Button, Dialog, useToast } from '@octapass/ui';
import type { Vault } from '@octapass/vault-client';
import { useState } from 'react';
import { Alert } from '../../components/Alert';
import { ConfirmDialog } from '../../components/ConfirmDialog';
import { t } from '../../i18n';
import { useVaults } from '../../lib/useItems';
import { useSharing } from '../../lib/useSharing';
import sharingStyles from '../sharing/Sharing.module.css';
import { Row } from './SettingsPage';

/** Settings → Security → Vault keys: gives a vault this account owns or manages a new key, on demand. */
export function VaultKeysRow() {
  const sharing = useSharing()!;
  const vaults = useVaults();
  const toast = useToast();
  const [open, setOpen] = useState(false);
  const [vault, setVault] = useState<Vault>();
  const rotatable = (vaults ?? []).filter((v) => (v.role === 'owner' || v.role === 'manage') && !v.untrusted);

  return (
    <>
      <Row label={t('vaultKeys.row')} description={t('vaultKeys.rowHelp')}>
        <Button variant="secondary" size="sm" icon="refresh" onClick={() => setOpen(true)}>
          {t('vaultKeys.action')}
        </Button>
      </Row>
      <Dialog open={open} onClose={() => setOpen(false)} closeLabel={t('common.close')} title={t('vaultKeys.title')} size="md">
        <p>{t('vaultKeys.intro')}</p>
        <Alert tone="info">{t('vaultKeys.limits')}</Alert>
        <ul className={sharingStyles.list}>
          {rotatable.map((v) => (
            <li key={v.id} className={sharingStyles.person}>
              <div className={sharingStyles.who}>
                <span className={sharingStyles.name}>{v.name}</span>
              </div>
              <div className={sharingStyles.controls}>
                <Button variant="secondary" size="sm" onClick={() => setVault(v)}>
                  {t('vaultKeys.rotate')}
                </Button>
              </div>
            </li>
          ))}
        </ul>
      </Dialog>
      <ConfirmDialog
        open={vault !== undefined}
        title={t('vaultKeys.confirmTitle', { vault: vault?.name ?? '' })}
        confirmLabel={t('vaultKeys.rotate')}
        tone="primary"
        onClose={() => setVault(undefined)}
        onConfirm={async () => {
          await sharing.rotateVaultKey(vault!.id);
          toast({ message: t('vaultKeys.done', { vault: vault!.name }), tone: 'success' });
        }}
      >
        {t('vaultKeys.confirmBody')}
      </ConfirmDialog>
    </>
  );
}
