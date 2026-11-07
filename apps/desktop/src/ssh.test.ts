import { describe, expect, it, vi } from 'vitest';
import { desktopSsh } from './ssh';
import type { Transport } from './transport';

function transport() {
  const invoke = vi.fn((_command: string, _args?: unknown) => Promise.resolve(undefined));
  return { transport: { invoke } as unknown as Transport, invoke };
}

describe('desktopSsh', () => {
  it('calls the app’s commands with their arguments', async () => {
    const { transport: t, invoke } = transport();
    const ssh = desktopSsh(t);
    await ssh.keys.generate('ed25519', 'me');
    expect(invoke).toHaveBeenLastCalledWith('ssh_generate', { kind: 'ed25519', comment: 'me' });
    await ssh.keys.read('text', 'pass');
    expect(invoke).toHaveBeenLastCalledWith('ssh_read', { text: 'text', passphrase: 'pass' });
    await ssh.home.read('id_ed25519');
    expect(invoke).toHaveBeenLastCalledWith('ssh_home_read', { name: 'id_ed25519', passphrase: undefined });
    await ssh.home.write('item', 'id_vault');
    expect(invoke).toHaveBeenLastCalledWith('ssh_home_write', { itemId: 'item', name: 'id_vault', passphrase: undefined, replace: false });
    await ssh.agent.setEnabled(true);
    expect(invoke).toHaveBeenLastCalledWith('ssh_agent_set_enabled', { enabled: true });
    await ssh.agent.connectConfig();
    expect(invoke).toHaveBeenLastCalledWith('ssh_config_connect');
  });
});
