import { Select } from '@octapass/ui';
import { useState } from 'react';
import { useService } from '../../app/ServiceContext';
import { t, type MessageKey } from '../../i18n';
import { PageHeader } from '../PageHeader';
import { CertificatesPanel } from './CertificatesPanel';
import { EncodingPanel } from './EncodingPanel';
import { HashPanel } from './HashPanel';
import { JwtPanel } from './JwtPanel';
import { KeysPanel } from './KeysPanel';
import { PasswordHashPanel } from './PasswordHashPanel';
import { RandomPanel } from './RandomPanel';
import { TotpPanel } from './TotpPanel';
import styles from './Tools.module.css';

const PANELS = {
  certificates: CertificatesPanel,
  keys: KeysPanel,
  jwt: JwtPanel,
  hash: HashPanel,
  encoding: EncodingPanel,
  random: RandomPanel,
  passwordHash: PasswordHashPanel,
  totp: TotpPanel,
} as const;

type PanelName = keyof typeof PANELS;

/** The developer toolkit (plan 16). Everything is computed on this device. */
export function ToolsPage() {
  const toolkit = useService().toolkit;
  const [panel, setPanel] = useState<PanelName>('certificates');
  const Panel = PANELS[panel];
  return (
    <div className={styles.page}>
      <PageHeader narrow title={t('tools.title')} subtitle={t('tools.subtitle')} />
      <div className={styles.body}>
        {!toolkit ? (
          <p>{t('tools.unavailable')}</p>
        ) : (
          <>
            <Select
              label={t('tools.choose')}
              value={panel}
              onChange={(e) => setPanel(e.target.value as PanelName)}
              options={(Object.keys(PANELS) as PanelName[]).map((name) => ({ value: name, label: t(`tools.panels.${name}` as MessageKey) }))}
            />
            <Panel />
            <p className={styles.note}>{t('tools.localNote')}</p>
          </>
        )}
      </div>
    </div>
  );
}
