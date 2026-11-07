import { Avatar, Button, Dialog, EmptyState, Spinner, Switch, TextField, useToast } from '@octapass/ui';
import { emptyDraft, findSameLogin, isTableType, type Item, type ItemDraft, type ItemType, type Vault } from '@octapass/vault-client';
import { useEffect, useMemo, useRef, useState, type FormEvent } from 'react';
import { useBlocker, useNavigate, useParams, useSearchParams } from 'react-router';
import { useService } from '../../app/ServiceContext';
import { Alert } from '../../components/Alert';
import { t, type MessageKey } from '../../i18n';
import { errorMessage } from '../../lib/errors';
import { parseScope, ITEM_TYPES } from '../../lib/scope';
import { useVaults } from '../../lib/useItems';
import { clearPendingDraft, pendingWifiDraft } from '../../lib/wifi';
import { cleanDraft, parseTags, validateDraft, type EditorErrors } from './editorModel';
import { CardSection, DocumentSection, IdentitySection, LoginSection, NoteSection, Section, WifiSection } from './EditorSections';
import { EnvironmentSection } from './Environment';
import { SshKeySection } from './SshKeys';
import { ToolItemSection } from '../tools/ItemFields';
import { CustomSection, TableSection, TemplateSection } from './TypedItems';
import { applyFileChanges, EditorFiles, hasFileChanges, NO_FILE_CHANGES, useAttachments, type FileChanges } from './Files';
import { useItem } from './ItemDetail';
import styles from './ItemEditor.module.css';

export function ItemEditor() {
  const { itemId } = useParams();
  const { item, error } = useItem(itemId);
  const vaults = useVaults();

  if (itemId && error) {
    return <EmptyState icon="alert" title={t('detail.notFound')}>{errorMessage(error)}</EmptyState>;
  }
  if ((itemId && !item) || !vaults) {
    return (
      <div className={styles.loading} aria-busy="true" aria-label={t('common.loading')}>
        <Spinner size={24} />
      </div>
    );
  }
  const vault = item && vaults.find((v) => v.id === item.vaultId);
  if (vault?.role === 'read') {
    return <EmptyState icon="lock" title={t('editor.readOnlyTitle')}>{t('detail.readOnly', { vault: vault.name })}</EmptyState>;
  }
  // Remount per item so the form state always starts from the item being edited.
  return <EditorForm key={item?.id ?? 'new'} original={item} vaults={vaults} />;
}

function useInitialDraft(original: Item | undefined, vaults: Vault[]): ItemDraft {
  const { scope } = useParams();
  const canAttach = Boolean(useService().attachments);
  const [search] = useSearchParams();
  return useMemo(() => {
    if (original) return structuredClone({ id: original.id, vaultId: original.vaultId, revision: original.revision, overview: original.overview, details: original.details });
    // A network to save ("Save this network?") arrives filled in.
    const pending = pendingWifiDraft();
    if (pending && vaults.some((v) => v.id === pending.vaultId && v.role !== 'read')) return pending;
    const parsed = parseScope(scope);
    const requested = search.get('type') as ItemType | null;
    const chosen = requested && ITEM_TYPES.includes(requested) ? requested : parsed.kind === 'type' ? parsed.type : 'login';
    // Documents are files, so they need a host with file storage.
    const type = chosen === 'document' && !canAttach ? 'login' : chosen;
    const writable = vaults.filter((v) => v.role !== 'read');
    const vaultId = (parsed.kind === 'vault' && writable.find((v) => v.id === parsed.vaultId)?.id) || writable.find((v) => v.type === 'personal')?.id || writable[0]!.id;
    const draft = emptyDraft(type, vaultId);
    if (parsed.kind === 'favorites') draft.overview.favorite = true;
    if (parsed.kind === 'pinned') draft.overview.pinned = true;
    return draft;
    // Only on mount: later URL changes don't reset a form in progress.
  }, []);
}

function EditorForm({ original, vaults }: { original: Item | undefined; vaults: Vault[] }) {
  const service = useService();
  const toast = useToast();
  const navigate = useNavigate();
  const { scope = 'all' } = useParams();
  const initial = useInitialDraft(original, vaults);
  const [draft, setDraft] = useState<ItemDraft>(initial);
  const [tagsText, setTagsText] = useState((initial.overview.tags ?? []).join(', '));
  const [errors, setErrors] = useState<EditorErrors>({});
  const [formError, setFormError] = useState<string>();
  const [saving, setSaving] = useState(false);
  const attachments = useAttachments();
  const [fileChanges, setFileChanges] = useState<FileChanges>(NO_FILE_CHANGES);
  const [fileError, setFileError] = useState<string>();
  /** A login the vault already has for the same site and username, while asking about a copy. */
  const [sameLogin, setSameLogin] = useState<Item>();
  const saved = useRef(false);
  const titleRef = useRef<HTMLInputElement>(null);

  const current = useMemo(() => ({ ...draft, overview: { ...draft.overview, tags: parseTags(tagsText) } }), [draft, tagsText]);
  const dirty = useMemo(
    () => JSON.stringify(cleanDraft(current, original)) !== JSON.stringify(cleanDraft(initial, original)) || hasFileChanges(fileChanges),
    [current, initial, original, fileChanges],
  );

  const blocker = useBlocker(({ currentLocation, nextLocation }) => dirty && !saved.current && currentLocation.pathname !== nextLocation.pathname && nextLocation.pathname !== '/lock');

  useEffect(() => {
    if (!dirty) return;
    const warn = (event: BeforeUnloadEvent) => event.preventDefault();
    window.addEventListener('beforeunload', warn);
    return () => window.removeEventListener('beforeunload', warn);
  }, [dirty]);

  useEffect(() => {
    if (!original) titleRef.current?.focus();
  }, [original]);

  useEffect(clearPendingDraft, []);

  const type = draft.overview.type;
  const writableVaults = vaults.filter((v) => v.role !== 'read' && !v.untrusted);
  const heading = original ? t('editor.editTitle', { title: original.overview.title }) : t(`editor.new.${type}` as MessageKey);
  const backTo = original ? `/items/${scope}/${original.id}` : `/items/${scope}`;

  function submit(event: FormEvent) {
    event.preventDefault();
    void save(false);
  }

  /** `copy`: the user saw that the vault has this login already and wants another one. */
  async function save(copy: boolean) {
    const next = validateDraft(current);
    setErrors(next);
    setFormError(undefined);
    // A document is its file: a new one needs one, and an edit can't remove the last without adding another.
    const keptFiles = ((original?.details as { attachments?: unknown[] } | undefined)?.attachments?.length ?? 0) - fileChanges.remove.length + fileChanges.add.length;
    const missingFile = type === 'document' && attachments && keptFiles === 0;
    setFileError(missingFile ? t('files.documentRequired') : undefined);
    if (Object.keys(next).length || missingFile) {
      setFormError(t('editor.fixErrors', { count: Object.keys(next).length + (missingFile ? 1 : 0) }));
      requestAnimationFrame(() => document.querySelector<HTMLElement>('[aria-invalid="true"]')?.focus());
      return;
    }
    setSaving(true);
    try {
      const cleaned = cleanDraft(current, original);
      if (!original && !copy) {
        // A check that fails (a locked vault, say) shouldn't stop the save itself.
        const same = await service
          .listItems()
          .then((items) => findSameLogin(items, cleaned, (id) => service.getItem(id)))
          .catch(() => undefined);
        if (same) {
          setSameLogin(same);
          setSaving(false);
          return;
        }
      }
      const result = await service.saveItem(cleaned);
      saved.current = true;
      if (attachments && hasFileChanges(fileChanges)) {
        // A conflict copy is a new item: it takes the new files, and the original keeps its own.
        const changes = result.id === original?.id ? fileChanges : { ...fileChanges, remove: [] };
        for (const failure of await applyFileChanges(attachments, result.id, changes)) toast({ message: failure, tone: 'danger' });
      }
      toast({ message: t('editor.saved', { title: result.overview.title }), tone: 'success' });
      navigate(`/items/${scope === 'trash' ? 'all' : scope}/${result.id}`, { replace: true });
    } catch (e) {
      setFormError(errorMessage(e));
      setSaving(false);
    }
  }

  const fieldError = (path: string) => (errors[path] ? t(errors[path]) : undefined);

  return (
    <form className={styles.editor} onSubmit={submit} noValidate aria-labelledby="editor-title">
      <div className={styles.toolbar}>
        <Button variant="ghost" onClick={() => navigate(backTo)}>
          {t('common.cancel')}
        </Button>
        <h1 id="editor-title" className={styles.toolbarTitle}>
          {heading}
        </h1>
        <Button type="submit" busy={saving}>
          {t('common.save')}
        </Button>
      </div>

      <div className={styles.content}>
        {formError && <Alert>{formError}</Alert>}

        <div className={styles.head}>
          <Avatar name={draft.overview.title || t(`types.${type}` as MessageKey)} size="lg" />
          <div className={styles.titleField}>
            <TextField
              ref={titleRef}
              label={t('fields.title')}
              value={draft.overview.title}
              onChange={(e) => setDraft((d) => ({ ...d, overview: { ...d.overview, title: e.target.value } }))}
              error={fieldError('title')}
              placeholder={t(`editor.titlePlaceholder.${type}` as MessageKey)}
              required
            />
          </div>
        </div>

        {type === 'document' && attachments && <EditorFiles original={original} changes={fileChanges} onChange={setFileChanges} document error={fileError} />}

        {type === 'login' || type === 'password' ? (
          <LoginSection draft={draft} setDraft={setDraft} fieldError={fieldError} />
        ) : type === 'card' ? (
          <CardSection draft={draft} setDraft={setDraft} fieldError={fieldError} />
        ) : type === 'identity' ? (
          <IdentitySection draft={draft} setDraft={setDraft} fieldError={fieldError} />
        ) : type === 'wifi' ? (
          <WifiSection draft={draft} setDraft={setDraft} fieldError={fieldError} />
        ) : type === 'environment' ? (
          <EnvironmentSection draft={draft} setDraft={setDraft} fieldError={fieldError} />
        ) : type === 'sshKey' ? (
          <SshKeySection draft={draft} setDraft={setDraft} fieldError={fieldError} />
        ) : isTableType(type) ? (
          <TableSection draft={draft} setDraft={setDraft} fieldError={fieldError} />
        ) : type === 'custom' ? (
          <CustomSection draft={draft} setDraft={setDraft} isNew={!original} />
        ) : type === 'customTemplate' ? (
          <TemplateSection draft={draft} setDraft={setDraft} />
        ) : type === 'document' ? (
          <DocumentSection draft={draft} setDraft={setDraft} />
        ) : type === 'certificate' || type === 'key' ? (
          <ToolItemSection draft={draft} setDraft={setDraft} />
        ) : (
          <NoteSection draft={draft} setDraft={setDraft} />
        )}

        {type !== 'document' && type !== 'customTemplate' && attachments && <EditorFiles original={original} changes={fileChanges} onChange={setFileChanges} document={false} />}

        <Section title={t('editor.organise')}>
          <label className={styles.selectField}>
            <span>{t('fields.vault')}</span>
            {/* An existing item changes vault through Move to…, which re-encrypts it under the new vault's key. */}
            <select value={draft.vaultId} disabled={Boolean(original)} onChange={(e) => setDraft((d) => ({ ...d, vaultId: e.target.value }))}>
              {writableVaults.map((v) => (
                <option key={v.id} value={v.id}>
                  {v.type === 'shared' ? t('editor.sharedVaultOption', { vault: v.name }) : v.type === 'family' ? t('editor.familyVaultOption', { vault: v.name }) : v.name}
                </option>
              ))}
            </select>
          </label>
          <TextField label={t('fields.tags')} value={tagsText} onChange={(e) => setTagsText(e.target.value)} hint={t('editor.tagsHint')} placeholder={t('editor.tagsPlaceholder')} />
          <Switch label={t('fields.favorite')} checked={Boolean(draft.overview.favorite)} onChange={(favorite) => setDraft((d) => ({ ...d, overview: { ...d.overview, favorite } }))} />
          <Switch label={t('fields.pinned')} checked={Boolean(draft.overview.pinned)} onChange={(pinned) => setDraft((d) => ({ ...d, overview: { ...d.overview, pinned } }))} />
        </Section>
      </div>

      <Dialog
        open={Boolean(sameLogin)}
        onClose={() => setSameLogin(undefined)}
        closeLabel={t('common.close')}
        title={t('editor.sameLoginTitle')}
        description={sameLogin ? t('editor.sameLoginBody', { title: sameLogin.overview.title, vault: vaults.find((v) => v.id === sameLogin.vaultId)?.name ?? '' }) : undefined}
        footer={
          <>
            <Button variant="secondary" onClick={() => setSameLogin(undefined)}>
              {t('editor.keepEditing')}
            </Button>
            <Button
              variant="secondary"
              onClick={() => {
                setSameLogin(undefined);
                void save(true);
              }}
            >
              {t('editor.saveAnyway')}
            </Button>
            {/* Leaving still asks about the changes here: the new password may be the one to keep. */}
            <Button onClick={() => sameLogin && navigate(`/items/all/${sameLogin.id}`)}>{t('editor.openSameLogin')}</Button>
          </>
        }
      />

      <Dialog
        open={blocker.state === 'blocked'}
        onClose={() => blocker.reset?.()}
        closeLabel={t('common.close')}
        title={t('editor.discardTitle')}
        description={t('editor.discardBody')}
        footer={
          <>
            <Button variant="secondary" onClick={() => blocker.reset?.()}>
              {t('editor.keepEditing')}
            </Button>
            <Button variant="danger" onClick={() => blocker.proceed?.()}>
              {t('editor.discard')}
            </Button>
          </>
        }
      />
    </form>
  );
}
