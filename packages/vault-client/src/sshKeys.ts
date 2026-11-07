// SSH keys (plans 01 and 16): the item's fields, the labels apps show, and the service that runs the
// core's key operations on this device. Private keys never leave the device unencrypted.

import { VaultError, type VaultErrorCode } from './errors';
import type { ItemDraft, SshKeyConfirmation, SshKeyDetails, SshKeyKind, SshKeyMaterial, SshKeyService } from './types';
import { SCHEMA_VERSION } from './types';

export const SSH_KEY_KINDS: readonly SshKeyKind[] = ['ed25519', 'ecdsaP256', 'ecdsaP384', 'rsa3072', 'rsa4096'];

/** What the core's SSH functions look like (`@octapass/core`). */
export interface SshCore {
  generateSshKey(kind: SshKeyKind, comment: string): SshKeyMaterial;
  readSshKey(text: string, passphrase?: string): SshKeyMaterial;
  writeSshKey(privateKey: string, comment: string, passphrase?: string): string;
}

const CORE_ERRORS: Record<string, VaultErrorCode> = {
  ssh_passphrase_required: 'sshPassphraseRequired',
  wrong_passphrase: 'wrongPassphrase',
  invalid_ssh_key: 'invalidSshKey',
  unsupported_ssh_key: 'unsupportedSshKey',
  ssh_public_key_only: 'sshPublicKeyOnly',
};

/** Runs a core SSH call, turning its error codes into `VaultError`s. */
export function sshCall<T>(fn: () => T): T {
  try {
    return fn();
  } catch (error) {
    const code = CORE_ERRORS[(error as { code?: string }).code ?? ''];
    if (code) throw new VaultError(code, (error as Error).message);
    throw error;
  }
}

/** A new SSH key item's details: empty until a key is generated or imported. */
export function emptySshKey(): SshKeyDetails {
  return { schemaVersion: SCHEMA_VERSION };
}

/** The draft's details with `key`'s fields; notes, custom fields and the rest stay. */
export function withSshKey(details: SshKeyDetails, key: SshKeyMaterial, passphrase?: string): SshKeyDetails {
  const next: SshKeyDetails = {
    ...details,
    privateKey: key.privateKey,
    publicKey: key.publicKey,
    keyType: key.keyType,
    fingerprint: key.fingerprint,
  };
  if (key.comment) next.comment = key.comment;
  if (passphrase) next.passphrase = passphrase;
  return next;
}

/** The `authorized_keys` line: the public key, a space and the comment. */
export function authorizedKeysLine(details: Pick<SshKeyDetails, 'publicKey' | 'comment'>): string {
  const key = details.publicKey?.trim() ?? '';
  const comment = details.comment?.trim();
  return comment && key ? `${key} ${comment}` : key;
}

const TYPE_LABELS: Record<string, string> = {
  'ssh-ed25519': 'Ed25519',
  'ecdsa-sha2-nistp256': 'ECDSA P-256',
  'ecdsa-sha2-nistp384': 'ECDSA P-384',
  'ecdsa-sha2-nistp521': 'ECDSA P-521',
  'ssh-rsa': 'RSA',
  'ssh-dss': 'DSA',
  'sk-ssh-ed25519@openssh.com': 'Ed25519 (security key)',
  'sk-ecdsa-sha2-nistp256@openssh.com': 'ECDSA P-256 (security key)',
};

/** "Ed25519", "ECDSA P-256", "RSA 4096": the type people know, with the size where it varies. */
export function sshKeyTypeLabel(details: Pick<SshKeyDetails, 'keyType' | 'publicKey'>): string | undefined {
  const type = details.keyType ?? details.publicKey?.split(/\s+/)[0];
  if (!type) return undefined;
  const label = TYPE_LABELS[type] ?? type;
  const bits = type === 'ssh-rsa' || type === 'ssh-dss' ? keyBits(details.publicKey) : undefined;
  return bits ? `${label} ${bits}` : label;
}

/** The RSA modulus or DSA prime size, read from the public key's second field. */
function keyBits(publicKey: string | undefined): number | undefined {
  const blob = publicKey?.trim().split(/\s+/)[1];
  if (!blob) return undefined;
  let bytes: Uint8Array;
  try {
    bytes = Uint8Array.from(atob(blob), (c) => c.charCodeAt(0));
  } catch {
    return undefined;
  }
  // string type, then (RSA) mpint e, mpint n — or (DSA) mpint p.
  let at = 0;
  const next = (): Uint8Array | undefined => {
    if (at + 4 > bytes.length) return undefined;
    const len = ((bytes[at]! << 24) | (bytes[at + 1]! << 16) | (bytes[at + 2]! << 8) | bytes[at + 3]!) >>> 0;
    const value = bytes.subarray(at + 4, at + 4 + len);
    at += 4 + len;
    return value.length === len ? value : undefined;
  };
  const type = new TextDecoder().decode(next());
  if (type === 'ssh-rsa') next();
  let n = next();
  if (!n) return undefined;
  let start = 0;
  while (start < n.length && n[start] === 0) start++;
  n = n.subarray(start);
  if (!n.length) return undefined;
  return (n.length - 1) * 8 + (32 - Math.clz32(n[0]!));
}

/** DSA and FIDO (`sk-`) keys are stored but can't be used yet. */
export function isUsableSshKey(details: Pick<SshKeyDetails, 'keyType'>): boolean {
  const type = details.keyType ?? '';
  return type === 'ssh-ed25519' || type === 'ssh-rsa' || type.startsWith('ecdsa-sha2-');
}

/** A file name for the private key: the title in lower case, `id_<type>` when there's none. */
export function sshKeyFileName(title: string, details: Pick<SshKeyDetails, 'keyType'>): string {
  const base = title
    .trim()
    .toLowerCase()
    .replace(/[^\p{L}\p{N}._-]+/gu, '_')
    .replace(/^[._]+|_+$/g, '');
  if (base) return base;
  const type = details.keyType ?? '';
  return type.includes('ed25519') ? 'id_ed25519' : type.includes('ecdsa') ? 'id_ecdsa' : type === 'ssh-dss' ? 'id_dsa' : 'id_rsa';
}

/** A new SSH key item from key material: titled, with the fingerprint as its list subtitle. */
export function sshKeyDraft(vaultId: string, title: string, key: SshKeyMaterial, passphrase?: string): ItemDraft {
  return {
    vaultId,
    overview: { schemaVersion: SCHEMA_VERSION, type: 'sshKey', title, subtitle: key.fingerprint },
    details: withSshKey(emptySshKey(), key, passphrase),
  };
}

/**
 * The service on top of the core's functions. `confirm` checks the master password or device unlock
 * again, which hosts do their own way.
 */
export function createSshKeyService(
  core: () => Promise<SshCore>,
  confirm: (proof: SshKeyConfirmation) => Promise<void>,
  canConfirmWithDevice: () => Promise<boolean>,
): SshKeyService {
  return {
    async generate(kind, comment) {
      const c = await core();
      return sshCall(() => c.generateSshKey(kind, comment.trim()));
    },
    async read(text, passphrase) {
      const c = await core();
      return sshCall(() => c.readSshKey(text, passphrase || undefined));
    },
    async write(privateKey, comment, passphrase) {
      const c = await core();
      return sshCall(() => c.writeSshKey(privateKey, comment.trim(), passphrase || undefined));
    },
    confirm,
    canConfirmWithDevice,
  };
}
