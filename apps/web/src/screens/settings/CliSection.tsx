import type { BackgroundStatus } from '@octapass/vault-client';
import { useEffect, useState } from 'react';
import { useService } from '../../app/ServiceContext';
import { t } from '../../i18n';
import { CopyButton } from '../vault/Fields';
import { Row, Section } from './SettingsPage';

/** Where the one-line installers are served (docs/platforms/cli.md#install). */
const SITE = 'https://octap.app';

/** The one command that installs the CLI on this desktop. */
export function cliInstallCommand(platform: BackgroundStatus['platform']): string {
  return platform === 'windows' ? `irm ${SITE}/install.ps1 | iex` : `curl -fsSL ${SITE}/install.sh | sh`;
}

/**
 * Settings → Command-line tool, in the Windows and Linux app: the CLI uses this app's account and
 * is unlocked whenever it is (plan 05). The Linux packages install it; elsewhere it's one command.
 */
export function CliSection() {
  const background = useService().background;
  const [platform, setPlatform] = useState<BackgroundStatus['platform']>();

  useEffect(() => {
    let live = true;
    background?.status().then(
      (status) => live && setPlatform(status.platform),
      () => undefined,
    );
    return () => {
      live = false;
    };
  }, [background]);

  if (!platform || platform === 'macos') return null;
  const command = cliInstallCommand(platform);
  return (
    <Section id="cli" title={t('cliTool.title')} description={t('cliTool.help')}>
      {platform === 'linux' && <p>{t('cliTool.linuxPackages')}</p>}
      <Row label={platform === 'linux' ? t('cliTool.otherwise') : t('cliTool.install')}>
        <span className="mono" dir="ltr">
          {command}
        </span>
        <CopyButton value={command} what={t('cliTool.command')} secret={false} />
      </Row>
    </Section>
  );
}
