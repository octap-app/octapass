import { Button, TextField } from '@octapass/ui';
import { useState } from 'react';
import { QrCode } from '../../components/QrCode';
import { t } from '../../i18n';
import { Card, Output, SaveToVault, ToolError, useTool } from './shared';
import styles from './Tools.module.css';

/** A new TOTP seed and its QR code, for adding 2FA to your own app. */
export function TotpPanel() {
  const { run, busy, error } = useTool();
  const [issuer, setIssuer] = useState('');
  const [account, setAccount] = useState('');
  const [made, setMade] = useState<{ secret: string; uri: string }>();

  return (
    <Card>
      <div className={styles.row}>
        <TextField label={t('tools.totp.issuer')} value={issuer} onChange={(e) => setIssuer(e.target.value)} />
        <TextField label={t('tools.totp.account')} value={account} onChange={(e) => setAccount(e.target.value)} />
      </div>
      <div className={styles.actions}>
        <Button icon="refresh" busy={busy} onClick={() => void run<{ secret: string; uri: string }>('totp.secret', { issuer, account }).then(setMade)}>
          {t('tools.totp.make')}
        </Button>
      </div>
      <ToolError message={error} />
      {made && (
        <>
          <QrCode value={made.uri} label={t('tools.totp.qr')} />
          <Output label={t('tools.totp.secret')} value={made.secret} />
          <Output label={t('tools.totp.uri')} value={made.uri} />
          <SaveToVault
            key={made.uri}
            defaultTitle={issuer || t('tools.totp.defaultTitle')}
            makeDraft={async (title) => ({
              overview: { schemaVersion: 1, type: 'login', title },
              details: { schemaVersion: 1, username: account || undefined, totp: made.uri },
            })}
          />
        </>
      )}
    </Card>
  );
}
