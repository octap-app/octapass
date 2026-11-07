import { describe, expect, it, vi } from 'vitest';
import { VaultError } from './errors';
import {
  authorizedKeysLine,
  createSshKeyService,
  emptySshKey,
  isUsableSshKey,
  sshCall,
  sshKeyDraft,
  sshKeyFileName,
  sshKeyTypeLabel,
  withSshKey,
  type SshCore,
} from './sshKeys';
import type { SshKeyMaterial } from './types';

const key: SshKeyMaterial = {
  privateKey: '-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n',
  publicKey: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample',
  keyType: 'ssh-ed25519',
  bits: 256,
  fingerprint: 'SHA256:cw5ZEN7m7AT7ImmissH+ctZwQN1s12PYZFmS2EC+Ovg',
  comment: 'me@laptop',
  usable: true,
};

function bytes(...parts: Uint8Array[]): Uint8Array {
  const all = new Uint8Array(parts.reduce((n, part) => n + part.length, 0));
  let at = 0;
  for (const part of parts) {
    all.set(part, at);
    at += part.length;
  }
  return all;
}

function sshString(value: string | Uint8Array): Uint8Array {
  const text = typeof value === 'string' ? new TextEncoder().encode(value) : value;
  const length = new Uint8Array(4);
  new DataView(length.buffer).setUint32(0, text.length);
  return bytes(length, text);
}

/** An `ssh-rsa` public key line whose modulus is `bits` long, for the size label. */
function rsaPublicKey(bits: number): string {
  const modulus = new Uint8Array(bits / 8 + 1);
  modulus[0] = 0;
  modulus[1] = 0x80;
  const exponent = new Uint8Array([1, 0, 1]);
  const blob = bytes(sshString('ssh-rsa'), sshString(exponent), sshString(modulus));
  return `ssh-rsa ${btoa(String.fromCharCode(...blob))}`;
}

describe('SSH key fields', () => {
  it('build the authorized_keys line with the comment, and without a duplicated space', () => {
    expect(authorizedKeysLine({ publicKey: 'ssh-ed25519 AAAA', comment: ' me@laptop ' })).toBe('ssh-ed25519 AAAA me@laptop');
    expect(authorizedKeysLine({ publicKey: 'ssh-ed25519 AAAA', comment: '  ' })).toBe('ssh-ed25519 AAAA');
    expect(authorizedKeysLine({})).toBe('');
  });

  it('name the type as people know it, with the size where it varies', () => {
    expect(sshKeyTypeLabel({ keyType: 'ssh-ed25519' })).toBe('Ed25519');
    expect(sshKeyTypeLabel({ keyType: 'ecdsa-sha2-nistp256' })).toBe('ECDSA P-256');
    expect(sshKeyTypeLabel({ keyType: 'ecdsa-sha2-nistp384' })).toBe('ECDSA P-384');
    expect(sshKeyTypeLabel({ keyType: 'ssh-rsa', publicKey: rsaPublicKey(3072) })).toBe('RSA 3072');
    expect(sshKeyTypeLabel({ keyType: 'ssh-dss' })).toBe('DSA');
    expect(sshKeyTypeLabel({ publicKey: 'sk-ssh-ed25519@openssh.com AAAA' })).toBe('Ed25519 (security key)');
    expect(sshKeyTypeLabel({})).toBeUndefined();
  });

  it('know that DSA and FIDO keys are stored but can not be used yet', () => {
    expect(isUsableSshKey({ keyType: 'ssh-ed25519' })).toBe(true);
    expect(isUsableSshKey({ keyType: 'ecdsa-sha2-nistp256' })).toBe(true);
    expect(isUsableSshKey({ keyType: 'ssh-rsa' })).toBe(true);
    expect(isUsableSshKey({ keyType: 'ssh-dss' })).toBe(false);
    expect(isUsableSshKey({ keyType: 'sk-ssh-ed25519@openssh.com' })).toBe(false);
    expect(isUsableSshKey({})).toBe(false);
  });

  it('name a downloaded file after the title, or id_<type> when there is none', () => {
    expect(sshKeyFileName('Laptop key for GitHub', { keyType: 'ssh-ed25519' })).toBe('laptop_key_for_github');
    expect(sshKeyFileName('Ünïcode key', { keyType: 'ssh-ed25519' })).toBe('ünïcode_key');
    expect(sshKeyFileName('...', { keyType: 'ssh-ed25519' })).toBe('id_ed25519');
    expect(sshKeyFileName('', { keyType: 'ecdsa-sha2-nistp384' })).toBe('id_ecdsa');
    expect(sshKeyFileName('', { keyType: 'ssh-rsa' })).toBe('id_rsa');
    expect(sshKeyFileName('', { keyType: 'ssh-dss' })).toBe('id_dsa');
  });

  it('keep what an edit adds and make a new item with the fingerprint as its subtitle', () => {
    const started = { ...emptySshKey(), notes: 'gates', customFields: [{ label: 'Host', value: 'github.com', hidden: false }] };
    expect(withSshKey(started, key, 'correct horse')).toEqual({
      schemaVersion: 1,
      notes: 'gates',
      customFields: [{ label: 'Host', value: 'github.com', hidden: false }],
      privateKey: key.privateKey,
      publicKey: key.publicKey,
      keyType: key.keyType,
      fingerprint: key.fingerprint,
      comment: key.comment,
      passphrase: 'correct horse',
    });
    expect(withSshKey(emptySshKey(), { ...key, comment: '' })).not.toHaveProperty('comment');
    expect(sshKeyDraft('v', 'Laptop key', key)).toEqual({
      vaultId: 'v',
      overview: { schemaVersion: 1, type: 'sshKey', title: 'Laptop key', subtitle: key.fingerprint },
      details: { ...emptySshKey(), privateKey: key.privateKey, publicKey: key.publicKey, keyType: key.keyType, fingerprint: key.fingerprint, comment: key.comment },
    });
  });
});

describe('the SSH key service', () => {
  const core = (): SshCore => ({
    generateSshKey: vi.fn(() => key),
    readSshKey: vi.fn(() => key),
    writeSshKey: vi.fn(() => '-----BEGIN OPENSSH PRIVATE KEY-----\nnew\n'),
  });

  it('runs the core with trimmed comments and no empty passphrase', async () => {
    const c = core();
    const confirm = vi.fn(async () => undefined);
    const service = createSshKeyService(async () => c, confirm, async () => true);
    expect(await service.generate('ed25519', '  me@laptop  ')).toEqual(key);
    expect(c.generateSshKey).toHaveBeenCalledWith('ed25519', 'me@laptop');
    expect(await service.read('file', '')).toEqual(key);
    expect(c.readSshKey).toHaveBeenCalledWith('file', undefined);
    expect(await service.write(key.privateKey, ' me@laptop ', 'pw')).toBe('-----BEGIN OPENSSH PRIVATE KEY-----\nnew\n');
    expect(c.writeSshKey).toHaveBeenCalledWith(key.privateKey, 'me@laptop', 'pw');
    await service.confirm({ password: 'pw' });
    expect(confirm).toHaveBeenCalledWith({ password: 'pw' });
    expect(await service.canConfirmWithDevice()).toBe(true);
  });

  it('turn the core error codes into VaultErrors the UI knows', async () => {
    const cases: [string, string][] = [
      ['ssh_passphrase_required', 'sshPassphraseRequired'],
      ['wrong_passphrase', 'wrongPassphrase'],
      ['invalid_ssh_key', 'invalidSshKey'],
      ['unsupported_ssh_key', 'unsupportedSshKey'],
      ['ssh_public_key_only', 'sshPublicKeyOnly'],
    ];
    for (const [coreCode, vaultCode] of cases) {
      expect(() =>
        sshCall(() => {
          throw Object.assign(new Error('no'), { code: coreCode });
        }),
      ).toThrow(VaultError);
      try {
        sshCall(() => {
          throw Object.assign(new Error('no'), { code: coreCode });
        });
      } catch (error) {
        expect((error as VaultError).code).toBe(vaultCode);
      }
    }
    const other = new Error('elsewhere');
    expect(() =>
      sshCall(() => {
        throw other;
      }),
    ).toThrow(other);
  });
});
