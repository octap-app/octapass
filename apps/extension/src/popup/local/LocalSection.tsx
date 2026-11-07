import { Button, useToast } from '@octapass/ui';
import { formatDate, t } from '@octapass/web/src/i18n';
import { downloadBlob } from '@octapass/web/src/lib/download';
import { errorMessage } from '@octapass/web/src/lib/errors';
import { useConfirmIdentity } from '@octapass/web/src/lib/identityGate';
import { Row, Section } from '@octapass/web/src/screens/settings/SettingsPage';
import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router';
import type { LocalMeta } from '../../shared/local';
import { tx } from '../../i18n';
import { useExtension } from '../ExtensionContext';
import { RecoveryCode } from './RecoveryCode';

export function backupFilename(now = new Date()): string {
  return `octapass-${now.toISOString().slice(0, 10)}.octapass-backup`;
}

/** Settings for a vault on this device only: backups, its recovery code, and Turn on sync. */
export function LocalSection() {
  const { api } = useExtension();
  const toast = useToast();
  const confirm = useConfirmIdentity();
  const navigate = useNavigate();
  const [meta, setMeta] = useState<Partial<LocalMeta>>();
  const [code, setCode] = useState<string>();

  useEffect(() => {
    void api.localInfo().then(setMeta);
  }, [api]);

  async function backUp() {
    if (!(await confirm({ reason: t('identityGate.body') }))) return;
    try {
      downloadBlob(await api.localBackup(), backupFilename());
      setMeta(await api.localInfo());
      toast({ message: tx('local.backedUp'), tone: 'success', icon: 'download' });
    } catch (e) {
      toast({ message: errorMessage(e), tone: 'danger' });
    }
  }

  return (
    <Section id="local" title={tx('local.sectionTitle')} description={tx('local.sectionHelp')}>
      <Row label={tx('local.backUp')} description={meta?.lastBackupAt ? tx('local.lastBackup', { date: formatDate(meta.lastBackupAt) }) : tx('local.neverBackedUp')}>
        <Button variant="secondary" size="sm" icon="download" onClick={() => void backUp()}>
          {tx('local.backUp')}
        </Button>
      </Row>
      {meta?.chip && <Row label={tx('local.chipBound')} description={tx('local.chipBoundHelp')} />}
      <Row label={tx('local.showCode')} description={code ? <RecoveryCode code={code} /> : tx('local.showCodeHelp')}>
        {!code && (
          <Button
            variant="secondary"
            size="sm"
            icon="eye"
            onClick={() =>
              void (async () => {
                if (await confirm({ reason: t('identityGate.body') })) setCode(await api.localRecoveryCode());
              })()
            }
          >
            {tx('local.showCode')}
          </Button>
        )}
      </Row>
      <Row label={tx('local.turnOnSync')} description={tx('local.turnOnSyncHelp')}>
        <Button size="sm" icon="refresh" onClick={() => navigate('/local/sync')}>
          {tx('local.turnOnSync')}
        </Button>
      </Row>
    </Section>
  );
}
