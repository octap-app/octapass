import { IconButton, Switch } from '@octapass/ui';
import type { ConnectClient, ConnectService } from '@octapass/vault-client';
import { useCallback, useEffect, useState } from 'react';
import { useService } from '../../app/ServiceContext';
import { formatDate, t } from '../../i18n';
import { useAction } from '../../lib/useAction';
import sharingStyles from '../sharing/Sharing.module.css';
import { Section } from './SettingsPage';
import styles from './SettingsPage.module.css';

const date = (unixSeconds: number) => formatDate(new Date(unixSeconds * 1000).toISOString());

/** Settings → Octa Pass Connect, in the desktop app: the switch and the approved programs. */
export function ConnectSection() {
  const connect = useService().connect;
  if (!connect) return null;
  return <Connect connect={connect} />;
}

function Connect({ connect }: { connect: ConnectService }) {
  const { run } = useAction();
  const [enabled, setEnabled] = useState(false);
  const [clients, setClients] = useState<ConnectClient[]>([]);
  const load = useCallback(async () => {
    const state = await connect.getState();
    setEnabled(state.enabled);
    setClients(state.clients);
  }, [connect]);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <Section id="connect" title={t('connect.title')} description={t('connect.help')}>
      <div className={styles.row}>
        <Switch
          label={t('connect.enabled')}
          description={t('connect.enabledHelp')}
          checked={enabled}
          onChange={(next) => {
            void run('enable', async () => {
              await connect.setEnabled(next);
              await load();
            });
          }}
        />
      </div>
      {clients.length === 0 ? (
        <p className={sharingStyles.empty}>{t('connect.noClients')}</p>
      ) : (
        <ul className={sharingStyles.list} aria-label={t('connect.clients')}>
          {clients.map((client) => (
            <li key={client.id} className={sharingStyles.person}>
              <div className={sharingStyles.who}>
                <div className={sharingStyles.whoText}>
                  <span className={sharingStyles.name}>{client.name}</span>
                  <span className={sharingStyles.meta}>
                    {client.program ?? t('connect.unknownProgram')} · {t('connect.expires', { date: date(client.expiresAt) })}
                    {client.lastUsedAt !== undefined && <> · {t('connect.lastUsed', { date: date(client.lastUsedAt) })}</>}
                  </span>
                </div>
              </div>
              <IconButton
                icon="trash"
                tone="danger"
                label={t('connect.revoke', { name: client.name })}
                onClick={() => {
                  void run(
                    'revoke',
                    async () => {
                      await connect.revokeClient(client.id);
                      await load();
                    },
                    t('connect.revoked'),
                  );
                }}
              />
            </li>
          ))}
        </ul>
      )}
    </Section>
  );
}
