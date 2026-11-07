import { Button, Checkbox, Dialog, IconButton, TextArea, TextField, useToast } from '@octapass/ui';
import {
  authorizedKeysLine,
  isUsableSshKey,
  isVaultError,
  sshKeyFileName,
  sshKeyTypeLabel,
  SSH_KEY_KINDS,
  withSshKey,
  type Item,
  type SshHomeKey,
  type SshKeyDetails,
  type SshKeyKind,
  type SshKeyMaterial,
} from '@octapass/vault-client';
import { useEffect, useRef, useState, type FormEvent } from 'react';
import { useService } from '../../app/ServiceContext';
import { Alert } from '../../components/Alert';
import { PasswordInput } from '../../components/PasswordInput';
import { t, type MessageKey } from '../../i18n';
import { downloadBlob } from '../../lib/download';
import { errorMessage } from '../../lib/errors';
import { unlockCoversReveal } from '../../lib/identityGate';
import { CustomFieldsSection, Section, type SectionProps } from './EditorSections';
import { CopyButton, Field, FieldList, SecretField } from './Fields';
import editorStyles from './ItemEditor.module.css';
import styles from './SshKeys.module.css';

/** Key files are a few kilobytes; anything much bigger isn't one. */
const MAX_KEY_FILE = 64 * 1024;

// ---------- Editor ----------

/** The editor's SSH key part: generate or import the key, then its comment, passphrase and notes. */
export function SshKeySection({ draft, setDraft, fieldError }: SectionProps) {
  const details = draft.details as SshKeyDetails;
  const set = (patch: Partial<SshKeyDetails>) => setDraft((d) => ({ ...d, details: { ...d.details, ...patch } }));
  const [replacing, setReplacing] = useState(false);
  const agent = useService().sshAgent;
  const useKey = (key: SshKeyMaterial, passphrase?: string) => {
    // A comment typed before generating or importing wins over the file's.
    setDraft((d) => {
      const current = d.details as SshKeyDetails;
      return { ...d, details: withSshKey(current, { ...key, comment: current.comment || key.comment }, passphrase) };
    });
    setReplacing(false);
  };

  return (
    <>
      <Section title={t('sshKey.key')}>
        {details.privateKey && !replacing ? (
          <div className={styles.summary}>
            <KeySummary details={details} />
            <Button variant="secondary" size="sm" icon="refresh" onClick={() => setReplacing(true)}>
              {t('sshKey.replace')}
            </Button>
          </div>
        ) : (
          <>
            {replacing && <Alert tone="warn">{t('sshKey.replaceConfirm')}</Alert>}
            <KeySource comment={details.comment ?? ''} onKey={useKey} error={fieldError('privateKey')} />
            {replacing && (
              <div>
                <Button variant="ghost" size="sm" onClick={() => setReplacing(false)}>
                  {t('common.cancel')}
                </Button>
              </div>
            )}
          </>
        )}
        <TextField
          label={t('sshKey.comment')}
          autoComplete="off"
          spellCheck={false}
          autoCapitalize="off"
          dir="ltr"
          value={details.comment ?? ''}
          onChange={(e) => set({ comment: e.target.value })}
          hint={t('sshKey.commentHint')}
        />
        <PasswordInput label={t('sshKey.passphrase')} autoComplete="new-password" value={details.passphrase ?? ''} onChange={(e) => set({ passphrase: e.target.value })} hint={t('sshKey.passphraseHint')} />
        {agent && <Checkbox label={t('sshKey.offerToAgent')} checked={details.sshAgent !== false} onChange={(e) => set({ sshAgent: e.target.checked ? undefined : false })} />}
      </Section>

      <CustomFieldsSection fields={details.customFields} onChange={(customFields) => set({ customFields })} />

      <Section title={t('fields.notes')}>
        <TextArea label={t('fields.notes')} hideLabel value={details.notes ?? ''} onChange={(e) => set({ notes: e.target.value })} />
      </Section>
    </>
  );
}

function KeySummary({ details }: { details: SshKeyDetails }) {
  return (
    <dl className={styles.facts}>
      <dt>{t('sshKey.type')}</dt>
      <dd>{sshKeyTypeLabel(details) ?? '—'}</dd>
      <dt>{t('sshKey.fingerprint')}</dt>
      <dd className="mono" dir="ltr">
        {details.fingerprint ?? '—'}
      </dd>
    </dl>
  );
}

/** Generate a key, choose a key file or paste one. Asks for the passphrase when the key has one. */
function KeySource({ comment, onKey, error }: { comment: string; onKey: (key: SshKeyMaterial, passphrase?: string) => void; error?: string }) {
  const ssh = useService().sshKeys;
  const toast = useToast();
  const [kind, setKind] = useState<SshKeyKind>('ed25519');
  const [pasted, setPasted] = useState('');
  const [busy, setBusy] = useState(false);
  const [locked, setLocked] = useState<string>();
  const input = useRef<HTMLInputElement>(null);

  if (!ssh) return <Alert tone="info">{t('sshKey.unavailable')}</Alert>;

  async function generate() {
    setBusy(true);
    try {
      onKey(await ssh!.generate(kind, comment));
    } catch (e) {
      toast({ message: errorMessage(e), tone: 'danger' });
    } finally {
      setBusy(false);
    }
  }

  async function read(text: string) {
    setBusy(true);
    try {
      onKey(await ssh!.read(text));
      setPasted('');
    } catch (e) {
      if (isVaultError(e, 'sshPassphraseRequired')) setLocked(text);
      else toast({ message: errorMessage(e), tone: 'danger' });
    } finally {
      setBusy(false);
    }
  }

  async function readFile(file: File) {
    if (file.size > MAX_KEY_FILE) {
      toast({ message: t('errors.invalidSshKey'), tone: 'danger' });
      return;
    }
    await read(await file.text());
  }

  return (
    <div className={styles.source}>
      <div className={styles.row}>
        <label className={editorStyles.selectField}>
          <span>{t('sshKey.kind')}</span>
          <select value={kind} onChange={(e) => setKind(e.target.value as SshKeyKind)}>
            {SSH_KEY_KINDS.map((k) => (
              <option key={k} value={k}>
                {t(`sshKey.kinds.${k}` as MessageKey)}
              </option>
            ))}
          </select>
        </label>
        <Button size="sm" icon="key" busy={busy} onClick={() => void generate()}>
          {busy ? t('sshKey.generating') : t('sshKey.generateAction')}
        </Button>
      </div>
      <p className={editorStyles.help}>{t('sshKey.kindHint')}</p>

      <div className={styles.row}>
        <Button variant="secondary" size="sm" icon="upload" disabled={busy} onClick={() => input.current?.click()}>
          {t('sshKey.importFile')}
        </Button>
        <input
          ref={input}
          type="file"
          hidden
          data-testid="ssh-key-file"
          onChange={(event) => {
            const file = event.target.files?.[0];
            event.target.value = '';
            if (file) void readFile(file);
          }}
        />
      </div>
      <p className={editorStyles.help}>{t('sshKey.importFileHint')}</p>

      <HomeKeys onKey={onKey} />

      <TextArea label={t('sshKey.paste')} mono rows={4} spellCheck={false} dir="ltr" value={pasted} onChange={(e) => setPasted(e.target.value)} error={error} placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" />
      {pasted.trim() && (
        <div>
          <Button variant="secondary" size="sm" busy={busy} onClick={() => void read(pasted)}>
            {t('sshKey.pasteAction')}
          </Button>
        </div>
      )}

      <PassphraseDialog
        text={locked}
        onClose={() => setLocked(undefined)}
        onKey={(key, passphrase) => {
          setLocked(undefined);
          setPasted('');
          onKey(key, passphrase);
        }}
      />
    </div>
  );
}

/** The keys already in `~/.ssh`, in the desktop app: choose one instead of finding its file. */
function HomeKeys({ onKey }: { onKey: (key: SshKeyMaterial, passphrase?: string) => void }) {
  const home = useService().sshHome;
  const toast = useToast();
  const [keys, setKeys] = useState<SshHomeKey[]>();
  const [locked, setLocked] = useState<string>();

  useEffect(() => {
    let live = true;
    home?.scan().then(
      (found) => live && setKeys(found),
      () => undefined,
    );
    return () => {
      live = false;
    };
  }, [home]);

  if (!home || !keys?.length) return null;

  async function use(key: SshHomeKey) {
    if (key.protected) {
      setLocked(key.name);
      return;
    }
    try {
      onKey(await home!.read(key.name));
    } catch (e) {
      toast({ message: errorMessage(e), tone: 'danger' });
    }
  }

  return (
    <div className={styles.homeKeys}>
      <p className={editorStyles.help}>{t('sshKey.homeHint')}</p>
      <ul>
        {keys.map((key) => (
          <li key={key.name}>
            <Button variant="secondary" size="sm" icon="key" onClick={() => void use(key)}>
              <span dir="ltr">{key.name}</span>
            </Button>
            {key.fingerprint && (
              <span className="mono" dir="ltr">
                {key.fingerprint}
              </span>
            )}
          </li>
        ))}
      </ul>
      <PassphraseDialog
        text={locked}
        read={(name, passphrase) => home.read(name, passphrase)}
        onClose={() => setLocked(undefined)}
        onKey={(key, passphrase) => {
          setLocked(undefined);
          onKey(key, passphrase);
        }}
      />
    </div>
  );
}

function PassphraseDialog({
  text,
  read,
  onClose,
  onKey,
}: {
  text: string | undefined;
  /** How `text` is read; pasted or chosen text by default. */
  read?: (text: string, passphrase: string) => Promise<SshKeyMaterial>;
  onClose: () => void;
  onKey: (key: SshKeyMaterial, passphrase?: string) => void;
}) {
  const ssh = useService().sshKeys;
  const [passphrase, setPassphrase] = useState('');
  const [keep, setKeep] = useState(true);
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    setPassphrase('');
    setError(undefined);
  }, [text]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!ssh || text === undefined) return;
    setBusy(true);
    try {
      onKey(await (read ? read(text, passphrase) : ssh.read(text, passphrase)), keep ? passphrase : undefined);
    } catch (e) {
      setError(isVaultError(e, 'wrongPassphrase') ? t('sshKey.wrongPassphrase') : errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog
      open={text !== undefined}
      onClose={onClose}
      closeLabel={t('common.close')}
      title={t('sshKey.passphraseTitle')}
      description={t('sshKey.passphraseBody')}
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            {t('common.cancel')}
          </Button>
          <Button type="submit" form="ssh-passphrase" busy={busy} disabled={!passphrase}>
            {t('sshKey.readAction')}
          </Button>
        </>
      }
    >
      <form id="ssh-passphrase" className={styles.dialogForm} onSubmit={(e) => void submit(e)}>
        <PasswordInput label={t('sshKey.passphrase')} autoComplete="off" autoFocus value={passphrase} onChange={(e) => setPassphrase(e.target.value)} error={error} />
        <Checkbox label={t('sshKey.keepPassphrase')} checked={keep} onChange={(e) => setKeep(e.target.checked)} />
      </form>
    </Dialog>
  );
}

// ---------- View ----------

/**
 * An SSH key's fields. `guard`: the private key is shown, copied or saved only after the master
 * password or device unlock is confirmed again (plan 16 §6), and not at all where this app can't
 * confirm. Showing it doesn't ask again when the user opened this session themselves
 * (`unlockCoversReveal`, plan 03 History 2026-11-05); saving it to a file always does. Pages
 * outside the vault (a share link, emergency access) show what they were given.
 */
export function SshKeyFields({ item, guard = false }: { item: Item; guard?: boolean }) {
  const details = item.details as SshKeyDetails;
  const service = useService();
  const ssh = service.sshKeys;
  const line = authorizedKeysLine(details);
  const typeLabel = sshKeyTypeLabel(details);
  const [confirmed, setConfirmed] = useState(false);
  const home = useService().sshHome;
  const [asking, setAsking] = useState<'show' | 'export' | 'home'>();
  const [shown, setShown] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [writing, setWriting] = useState(false);
  const toast = useToast();
  const fileName = sshKeyFileName(item.overview.title, details);

  // Confirming covers this item while it's open.
  useEffect(() => {
    setConfirmed(false);
    setShown(false);
  }, [item.id]);

  const afterConfirm = (what: 'show' | 'export' | 'home') => (what === 'show' ? setShown(true) : what === 'home' ? setWriting(true) : setExporting(true));
  const request = (what: 'show' | 'export' | 'home') => {
    if (confirmed || !guard) return afterConfirm(what);
    if (what !== 'show') return setAsking(what);
    // The unlock covers showing it, not `confirmed`: saving it still asks.
    void unlockCoversReveal(service).then((covered) => (covered ? setShown(true) : setAsking('show')));
  };
  const canExport = Boolean(details.privateKey && ssh);
  const canShow = Boolean(details.privateKey && (!guard || ssh));

  function savePublic() {
    downloadBlob(new Blob([`${line}\n`], { type: 'text/plain' }), `${fileName}.pub`);
    toast({ message: t('sshKey.exported', { file: `${fileName}.pub` }), tone: 'success', icon: 'download' });
  }

  return (
    <>
      <FieldList>
        {line && (
          <Field label={t('sshKey.publicKey')} value={line} what={t('sshKey.publicKey')} mono ltr>
            <span className={styles.publicKey} dir="ltr">
              {line}
            </span>
          </Field>
        )}
        <Field label={t('sshKey.fingerprint')} value={details.fingerprint} mono ltr />
        <Field label={t('sshKey.type')} value={typeLabel} copy={false} />
        <Field label={t('sshKey.comment')} value={details.comment} ltr />
        {canShow && (
          <Field
            label={t('sshKey.privateKey')}
            copy={false}
            actions={
              shown ? (
                <>
                  <IconButton size="sm" icon="eyeOff" label={t('sshKey.hidePrivate')} onClick={() => setShown(false)} />
                  <CopyButton value={details.privateKey!} what={t('sshKey.privateKey')} />
                </>
              ) : (
                <Button variant="secondary" size="sm" icon="eye" onClick={() => request('show')}>
                  {t('sshKey.showPrivate')}
                </Button>
              )
            }
          >
            {shown ? <pre className={styles.privateKey}>{details.privateKey}</pre> : <span aria-label={t('detail.hiddenValue')}>{'•'.repeat(16)}</span>}
          </Field>
        )}
        <SecretField label={t('sshKey.passphrase')} value={details.passphrase} />
      </FieldList>

      {typeLabel && details.keyType && !isUsableSshKey(details) && <Alert tone="info">{t('sshKey.notUsable', { type: typeLabel })}</Alert>}

      {(line || canExport) && (
        <div className={styles.actions}>
          {canExport && (
            <Button variant="secondary" size="sm" icon="download" onClick={() => request('export')}>
              {t('sshKey.exportPrivate')}
            </Button>
          )}
          {line && (
            <Button variant="secondary" size="sm" icon="download" onClick={savePublic}>
              {t('sshKey.exportPublic')}
            </Button>
          )}
          {home && canExport && (
            <Button variant="secondary" size="sm" icon="download" onClick={() => request('home')}>
              {t('sshKey.writeHome')}
            </Button>
          )}
        </div>
      )}

      {details.customFields && details.customFields.length > 0 && (
        <FieldList>
          {details.customFields.map((f, i) => (f.hidden ? <SecretField key={i} label={f.label} value={f.value} /> : <Field key={i} label={f.label} value={f.value} />))}
        </FieldList>
      )}
      {details.notes && (
        <FieldList title={t('fields.notes')}>
          <Field label={t('fields.notes')} value={details.notes} multiline secret />
        </FieldList>
      )}

      <ConfirmDialog
        open={asking !== undefined}
        onClose={() => setAsking(undefined)}
        onConfirmed={() => {
          setConfirmed(true);
          const what = asking!;
          setAsking(undefined);
          afterConfirm(what);
        }}
      />
      {canExport && <ExportDialog open={exporting} onClose={() => setExporting(false)} details={details} fileName={fileName} />}
      {home && canExport && <WriteHomeDialog open={writing} onClose={() => setWriting(false)} itemId={item.id} fileName={fileName} passphrase={details.passphrase} />}
    </>
  );
}

/** Writes the key to `~/.ssh`, with a passphrase when it has one, after the user confirmed. */
function WriteHomeDialog({ open, onClose, itemId, fileName, passphrase }: { open: boolean; onClose: () => void; itemId: string; fileName: string; passphrase?: string | undefined }) {
  const home = useService().sshHome;
  const toast = useToast();
  const [name, setName] = useState(fileName);
  const [filePassphrase, setFilePassphrase] = useState(passphrase ?? '');
  const [replace, setReplace] = useState(false);
  const [exists, setExists] = useState(false);
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!open) return;
    setName(fileName);
    setFilePassphrase(passphrase ?? '');
    setReplace(false);
    setExists(false);
    setError(undefined);
  }, [open, fileName, passphrase]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!home) return;
    setBusy(true);
    setError(undefined);
    try {
      const path = await home.write(itemId, name.trim(), filePassphrase || undefined, replace);
      toast({ message: t('sshKey.exported', { file: path }), tone: 'success', icon: 'download' });
      onClose();
    } catch (e) {
      if (isVaultError(e, 'alreadyExists')) setExists(true);
      else setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog
      open={open}
      onClose={onClose}
      closeLabel={t('common.close')}
      title={t('sshKey.writeHomeTitle')}
      description={t('sshKey.writeHomeBody')}
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            {t('common.cancel')}
          </Button>
          <Button type="submit" form="ssh-write-home" busy={busy} disabled={!name.trim() || (exists && !replace)}>
            {t('sshKey.exportAction')}
          </Button>
        </>
      }
    >
      <form id="ssh-write-home" className={styles.dialogForm} onSubmit={(e) => void submit(e)}>
        <TextField label={t('sshKey.writeHomeName')} dir="ltr" value={name} onChange={(e) => setName(e.target.value)} error={error} />
        <PasswordInput label={t('sshKey.exportPassphrase')} autoComplete="new-password" value={filePassphrase} onChange={(e) => setFilePassphrase(e.target.value)} hint={t('sshKey.exportPassphraseHint')} />
        {exists && <Checkbox label={t('sshKey.writeHomeReplace')} checked={replace} onChange={(e) => setReplace(e.target.checked)} />}
      </form>
    </Dialog>
  );
}

/** Asks for the master password, or device unlock where it's on, before a private key is shown or saved. */
export function ConfirmDialog({ open, onClose, onConfirmed }: { open: boolean; onClose: () => void; onConfirmed: () => void }) {
  const ssh = useService().sshKeys;
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [device, setDevice] = useState(false);

  useEffect(() => {
    if (!open) return;
    setPassword('');
    setError(undefined);
    let live = true;
    ssh?.canConfirmWithDevice().then(
      (yes) => live && setDevice(yes),
      () => undefined,
    );
    return () => {
      live = false;
    };
  }, [open, ssh]);

  async function confirm(proof: { password: string } | { device: true }) {
    if (!ssh) return;
    setBusy(true);
    setError(undefined);
    try {
      await ssh.confirm(proof);
      onConfirmed();
    } catch (e) {
      setError(isVaultError(e, 'invalidCredentials') ? t('sshKey.wrongPassword') : errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog
      open={open}
      onClose={onClose}
      closeLabel={t('common.close')}
      title={t('sshKey.confirmTitle')}
      description={t('sshKey.confirmBody')}
      footer={
        <>
          {device && (
            <Button variant="secondary" icon="fingerprint" disabled={busy} onClick={() => void confirm({ device: true })}>
              {t('sshKey.confirmDevice')}
            </Button>
          )}
          <Button type="submit" form="ssh-confirm" busy={busy} disabled={!password}>
            {t('sshKey.confirmAction')}
          </Button>
        </>
      }
    >
      <form
        id="ssh-confirm"
        className={styles.dialogForm}
        onSubmit={(e) => {
          e.preventDefault();
          void confirm({ password });
        }}
      >
        <PasswordInput label={t('fields.masterPassword')} autoComplete="current-password" autoFocus value={password} onChange={(e) => setPassword(e.target.value)} error={error} />
      </form>
    </Dialog>
  );
}

function ExportDialog({ open, onClose, details, fileName }: { open: boolean; onClose: () => void; details: SshKeyDetails; fileName: string }) {
  const ssh = useService().sshKeys!;
  const toast = useToast();
  const [passphrase, setPassphrase] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (open) setPassphrase(details.passphrase ?? '');
  }, [open, details.passphrase]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    try {
      const text = await ssh.write(details.privateKey!, details.comment ?? '', passphrase);
      downloadBlob(new Blob([text], { type: 'application/x-pem-file' }), fileName);
      toast({ message: t('sshKey.exported', { file: fileName }), tone: 'success', icon: 'download' });
      onClose();
    } catch (e) {
      toast({ message: errorMessage(e), tone: 'danger' });
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog
      open={open}
      onClose={onClose}
      closeLabel={t('common.close')}
      title={t('sshKey.exportTitle')}
      description={t('sshKey.exportBody')}
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            {t('common.cancel')}
          </Button>
          <Button type="submit" form="ssh-export" icon="download" busy={busy}>
            {t('sshKey.exportAction')}
          </Button>
        </>
      }
    >
      <form id="ssh-export" className={styles.dialogForm} onSubmit={(e) => void submit(e)}>
        <PasswordInput label={t('sshKey.exportPassphrase')} autoComplete="new-password" value={passphrase} onChange={(e) => setPassphrase(e.target.value)} hint={t('sshKey.exportPassphraseHint')} />
      </form>
    </Dialog>
  );
}

