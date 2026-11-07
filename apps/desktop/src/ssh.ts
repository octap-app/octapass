import type { SshAgentService, SshAgentStatus, SshHomeKey, SshHomeService, SshKeyMaterial, SshKeyService } from '@octapass/vault-client';
import type { Transport } from './transport';

export interface DesktopSsh {
  /** The key operations; the service adds confirming it's the user. */
  keys: Pick<SshKeyService, 'generate' | 'read' | 'write'>;
  home: SshHomeService;
  agent: SshAgentService;
}

/** SSH keys, `~/.ssh` and the agent over the app's commands (`src-tauri/src/ssh.rs`). */
export function desktopSsh(transport: Transport): DesktopSsh {
  return {
    keys: {
      generate: (kind, comment) => transport.invoke<SshKeyMaterial>('ssh_generate', { kind, comment }),
      read: (text, passphrase) => transport.invoke<SshKeyMaterial>('ssh_read', { text, passphrase }),
      write: (privateKey, comment, passphrase) => transport.invoke<string>('ssh_write', { privateKey, comment, passphrase }),
    },
    home: {
      scan: () => transport.invoke<SshHomeKey[]>('ssh_home_scan'),
      read: (name, passphrase) => transport.invoke<SshKeyMaterial>('ssh_home_read', { name, passphrase }),
      write: (itemId, name, passphrase, replace = false) => transport.invoke<string>('ssh_home_write', { itemId, name, passphrase, replace }),
    },
    agent: {
      status: () => transport.invoke<SshAgentStatus>('ssh_agent_status'),
      setEnabled: (enabled) => transport.invoke<SshAgentStatus>('ssh_agent_set_enabled', { enabled }),
      connectConfig: () => transport.invoke<SshAgentStatus>('ssh_config_connect'),
      disconnectConfig: () => transport.invoke<SshAgentStatus>('ssh_config_disconnect'),
    },
  };
}
