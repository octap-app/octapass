import { Button, Switch, useToast } from '@octapass/ui';
import { sshKeyTypeLabel, type SshAgentStatus } from '@octapass/vault-client';
import { useEffect, useState } from 'react';
import { useService } from '../../app/ServiceContext';
import { Alert } from '../../components/Alert';
import { t } from '../../i18n';
import { errorMessage } from '../../lib/errors';
import { Row, Section } from './SettingsPage';
import styles from './SettingsPage.module.css';

/** Settings → SSH agent, in the desktop app. */
export function SshAgentSection() {
  const agent = useService().sshAgent;
  const toast = useToast();
  const [status, setStatus] = useState<SshAgentStatus>();
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let live = true;
    agent?.status().then(
      (next) => live && setStatus(next),
      () => undefined,
    );
    return () => {
      live = false;
    };
  }, [agent]);

  if (!agent || !status) return null;

  async function run(action: () => Promise<SshAgentStatus>) {
    setBusy(true);
    try {
      setStatus(await action());
    } catch (e) {
      toast({ message: errorMessage(e), tone: 'danger' });
    } finally {
      setBusy(false);
    }
  }

  return (
    <Section id="ssh-agent" title={t('sshAgent.title')} description={t('sshAgent.help')}>
      <div className={styles.row}>
        <Switch label={t('sshAgent.enable')} description={t('sshAgent.enableHelp')} checked={status.enabled} disabled={busy} onChange={(enabled) => void run(() => agent.setEnabled(enabled))} />
      </div>
      {status.error && <Alert tone="warn">{t('sshAgent.notRunning', { error: status.error })}</Alert>}
      {status.enabled && (
        <>
          {status.windows && <Alert tone="info">{t('sshAgent.windowsHelp')}</Alert>}
          {status.endpoint && (
            <Row label={t('sshAgent.socket')}>
              <span className="mono" dir="ltr">
                {status.endpoint}
              </span>
            </Row>
          )}
          <Row label={status.configConnected ? t('sshAgent.configConnected') : t('sshAgent.configConnectHelp')}>
            {status.configConnected ? (
              <Button variant="secondary" size="sm" disabled={busy} onClick={() => void run(() => agent.disconnectConfig())}>
                {t('sshAgent.configDisconnect')}
              </Button>
            ) : (
              <Button variant="secondary" size="sm" disabled={busy} onClick={() => void run(() => agent.connectConfig())}>
                {t('sshAgent.configConnect')}
              </Button>
            )}
          </Row>
          {status.endpoint && !status.windows && <p>{t('sshAgent.envHelp', { path: status.endpoint })}</p>}
          {status.keys.length > 0 ? (
            <Row label={t('sshAgent.keys', { count: status.keys.length })}>
              <span>
                {status.keys.map((key) => (
                  <bdi key={key.fingerprint}>
                    {key.title} ({sshKeyTypeLabel(key)}){' '}
                  </bdi>
                ))}
              </span>
            </Row>
          ) : (
            <p>{t('sshAgent.lockedKeys')}</p>
          )}
        </>
      )}
    </Section>
  );
}
