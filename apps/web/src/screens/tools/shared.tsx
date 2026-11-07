import { Button, IconButton, Select, TextField, useToast } from '@octapass/ui';
import { isVaultError, type ItemDraft, type Vault } from '@octapass/vault-client';
import { useCallback, useState, type ReactNode } from 'react';
import { useNavigate } from 'react-router';
import { useService } from '../../app/ServiceContext';
import { t, type MessageKey } from '../../i18n';
import { useCopy } from '../../lib/clipboard';
import { downloadBlob } from '../../lib/download';
import { errorMessage } from '../../lib/errors';
import { useConfirmIdentity, useConfirmReveal } from '../../lib/identityGate';
import { useVaults } from '../../lib/useItems';
import styles from './Tools.module.css';

// The Tools section's shared parts. Every tool is a call into the Rust core on this device; panels
// only collect input and show what comes back.

const TOOL_ERRORS = new Set([
  'invalid_tool_input',
  'invalid_encoding',
  'unsupported_algorithm',
  'invalid_hash_parameters',
  'invalid_key_file',
  'private_key_required',
  'key_algorithm_mismatch',
  'invalid_token',
  'no_matching_key',
  'invalid_certificate',
  'certificate_key_mismatch',
  'invalid_pkcs12',
  'name_not_permitted',
  'wrong_passphrase',
  'decryption_failed',
  'invalid_signature',
  'pgp_unavailable',
]);

export function toolError(error: unknown): string {
  if (isVaultError(error, 'toolFailed')) {
    const code = (error as Error).message;
    return t((TOOL_ERRORS.has(code) ? `tools.errors.${code}` : 'tools.errors.unknown') as MessageKey);
  }
  return errorMessage(error);
}

/** Runs tools with one busy state and one error line. */
export function useTool() {
  const toolkit = useService().toolkit!;
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();

  const run = useCallback(
    async <T,>(op: string, input: object): Promise<T | undefined> => {
      setBusy(true);
      setError(undefined);
      try {
        return await toolkit.run<T>(op, input);
      } catch (e) {
        setError(toolError(e));
        return undefined;
      } finally {
        setBusy(false);
      }
    },
    [toolkit],
  );

  return { toolkit, run, busy, error, setError };
}

export function ToolError({ message }: { message?: string }) {
  return message ? (
    <p role="alert" className={styles.bad}>
      {message}
    </p>
  ) : null;
}

export function Card({ title, children }: { title?: string; children: ReactNode }) {
  return (
    <section className={styles.card}>
      {title && <h2>{title}</h2>}
      {children}
    </section>
  );
}

/** Text a tool made, with copy and, when `fileName` is given, download. */
export function Output({ label, value, fileName, gated = false }: { label: string; value: string; fileName?: string; gated?: boolean }) {
  const copy = useCopy();
  const confirm = useConfirmIdentity();
  const confirmReveal = useConfirmReveal();
  const [shown, setShown] = useState(!gated);

  // Showing and copying: the unlock covers them. Saving a file of it is an export: every time.
  async function confirmed(gate = confirmReveal): Promise<boolean> {
    return !gated || gate({ reason: t('identityGate.body') });
  }

  async function toggle() {
    if (shown || (await confirmed())) setShown(!shown);
  }

  async function copyValue() {
    if (await confirmed()) await copy(value, label, { secret: gated });
  }

  async function save() {
    if (await confirmed(confirm)) downloadBlob(new Blob([value], { type: 'text/plain' }), fileName!);
  }

  return (
    <div className={styles.output}>
      <div className={styles.outputHead}>
        <span>{label}</span>
        <span className={styles.actions}>
          {gated && <IconButton size="sm" icon={shown ? 'eyeOff' : 'eye'} label={t(shown ? 'tools.hide' : 'tools.show')} onClick={() => void toggle()} />}
          <IconButton size="sm" icon="copy" label={t('copy.action', { what: label })} onClick={() => void copyValue()} />
          {fileName && <IconButton size="sm" icon="download" label={t('tools.download')} onClick={() => void save()} />}
        </span>
      </div>
      <pre className={styles.pre} dir="ltr" tabIndex={0}>
        {shown ? value : '••••••••••••'}
      </pre>
    </div>
  );
}

/** The writable vaults, personal first, as Select options. */
export function vaultOptions(vaults: Vault[] | undefined) {
  return (vaults ?? []).filter((vault) => vault.role !== 'read' && !vault.untrusted).map((vault) => ({ value: vault.id, label: vault.name }));
}

/** "Save to vault": `makeDraft` builds `{ overview, details }` in the core. */
export function SaveToVault({ defaultTitle, makeDraft }: { defaultTitle: string; makeDraft: (title: string) => Promise<Pick<ItemDraft, 'overview' | 'details'> | undefined> }) {
  const service = useService();
  const vaults = useVaults();
  const options = vaultOptions(vaults);
  const toast = useToast();
  const navigate = useNavigate();
  const [title, setTitle] = useState(defaultTitle);
  const [vaultId, setVaultId] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [saved, setSaved] = useState(false);

  async function save() {
    const target = vaultId ?? options[0]?.value;
    if (!target) return;
    setBusy(true);
    try {
      const draft = await makeDraft(title.trim() || defaultTitle);
      if (!draft) return;
      const item = await service.saveItem({ ...draft, vaultId: target } as ItemDraft);
      setSaved(true);
      toast({ message: t('tools.saved'), tone: 'success' });
      void navigate(`/items/all/${item.id}`);
    } catch (e) {
      toast({ message: toolError(e), tone: 'danger' });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className={styles.row}>
      <TextField label={t('tools.itemTitle')} value={title} onChange={(e) => setTitle(e.target.value)} autoComplete="off" />
      {options.length > 1 && <Select label={t('fields.vault')} options={options} value={vaultId ?? options[0]?.value} onChange={(e) => setVaultId(e.target.value)} />}
      <Button icon="lock" busy={busy} disabled={saved || !options.length} onClick={() => void save()} style={{ flex: '0 0 auto' }}>
        {saved ? t('tools.savedShort') : t('tools.save')}
      </Button>
    </div>
  );
}

/** Reads a chosen file as text, or as base64 when it isn't text. */
export async function readFile(file: File): Promise<string> {
  const bytes = new Uint8Array(await file.arrayBuffer());
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return base64Of(bytes);
  }
}

export function base64Of(bytes: Uint8Array): string {
  let text = '';
  for (let index = 0; index < bytes.length; index += 0x8000) text += String.fromCharCode(...bytes.subarray(index, index + 0x8000));
  return btoa(text);
}

export function bytesOf(base64: string): Uint8Array<ArrayBuffer> {
  const text = atob(base64);
  const bytes = new Uint8Array(text.length);
  for (let index = 0; index < text.length; index += 1) bytes[index] = text.charCodeAt(index);
  return bytes;
}

export function FileButton({ label, onFile }: { label: string; onFile: (file: File) => void }) {
  return (
    <label className={styles.note}>
      {label}{' '}
      <input
        type="file"
        onChange={(e) => {
          const file = e.target.files?.[0];
          if (file) onFile(file);
          e.target.value = '';
        }}
      />
    </label>
  );
}

export const KEY_TYPES = [
  { value: 'ed25519', label: 'Ed25519' },
  { value: 'p256', label: 'ECDSA P-256' },
  { value: 'p384', label: 'ECDSA P-384' },
  { value: 'rsa2048', label: 'RSA 2048' },
  { value: 'rsa3072', label: 'RSA 3072' },
  { value: 'rsa4096', label: 'RSA 4096' },
];
