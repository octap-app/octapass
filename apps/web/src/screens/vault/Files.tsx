import { Button, Icon, IconButton, Spinner, useToast, type IconName } from '@octapass/ui';
import { attachmentsOf, type Attachment, type AttachmentService, type FileSource, type Item, type NativeFiles, type PickedFile } from '@octapass/vault-client';
import { useEffect, useRef, useState, type DragEvent, type ReactNode } from 'react';
import { useService } from '../../app/ServiceContext';
import { ConfirmDialog } from '../../components/ConfirmDialog';
import { formatBytes, t } from '../../i18n';
import { downloadBlob } from '../../lib/download';
import { errorMessage } from '../../lib/errors';
import styles from './Files.module.css';

/** "PDF", "PNG": the extension, or the media subtype when the name has none. */
function kindOf(file: { name: string; type: string }): string | undefined {
  const extension = /\.([a-z0-9]{1,8})$/i.exec(file.name)?.[1];
  return (extension ?? file.type.split('/')[1])?.toUpperCase() || undefined;
}

function describe(file: { name: string; type: string; size: number }): string {
  const kind = kindOf(file);
  return kind ? t('files.sizeAndType', { size: formatBytes(file.size), type: kind }) : formatBytes(file.size);
}

/** Drop files anywhere on the element. `dragging` is true while files are over it. */
function useDrop(onFiles: (files: File[]) => void, enabled: boolean) {
  const [depth, setDepth] = useState(0);
  const hasFiles = (event: DragEvent) => enabled && Array.from(event.dataTransfer.types).includes('Files');
  return {
    dragging: depth > 0,
    handlers: {
      onDragEnter: (event: DragEvent) => {
        if (!hasFiles(event)) return;
        event.preventDefault();
        setDepth((d) => d + 1);
      },
      onDragOver: (event: DragEvent) => {
        if (!hasFiles(event)) return;
        event.preventDefault();
        event.dataTransfer.dropEffect = 'copy';
      },
      onDragLeave: (event: DragEvent) => {
        if (hasFiles(event)) setDepth((d) => Math.max(0, d - 1));
      },
      onDrop: (event: DragEvent) => {
        if (!hasFiles(event)) return;
        event.preventDefault();
        setDepth(0);
        onFiles(Array.from(event.dataTransfer.files));
      },
    },
  };
}

/** A button that opens the file picker. */
function PickFiles({ label, multiple = true, onFiles, disabled }: { label: string; multiple?: boolean; onFiles: (files: File[]) => void; disabled?: boolean }) {
  const input = useRef<HTMLInputElement>(null);
  return (
    <>
      <Button variant="secondary" size="sm" icon="paperclip" disabled={disabled} onClick={() => input.current?.click()}>
        {label}
      </Button>
      <input
        ref={input}
        type="file"
        multiple={multiple}
        hidden
        data-testid="file-input"
        onChange={(event) => {
          const files = Array.from(event.target.files ?? []);
          event.target.value = '';
          if (files.length) onFiles(files);
        }}
      />
    </>
  );
}

const SOURCES: Record<FileSource, { icon: IconName; label: 'files.fromFiles' | 'files.fromPhotos' | 'files.fromCamera' }> = {
  files: { icon: 'paperclip', label: 'files.fromFiles' },
  photos: { icon: 'image', label: 'files.fromPhotos' },
  camera: { icon: 'camera', label: 'files.fromCamera' },
};

/** The phone's own pickers, one button each. They hand back descriptions; the files stay with the app. */
function PickNative({ native, onPicked, disabled }: { native: NativeFiles; onPicked: (files: PickedFile[]) => void; disabled?: boolean }) {
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  async function pick(source: FileSource) {
    setBusy(true);
    try {
      const picked = await native.pick(source);
      if (picked.length) onPicked(picked);
    } catch (error) {
      toast({ message: errorMessage(error), tone: 'danger' });
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className={styles.sources}>
      {native.sources.map((source) => (
        <Button key={source} variant="secondary" size="sm" icon={SOURCES[source].icon} disabled={disabled || busy} onClick={() => void pick(source)}>
          {t(SOURCES[source].label)}
        </Button>
      ))}
    </div>
  );
}

function FileRow({ file, note, actions, muted }: { file: { name: string; type: string; size: number }; note?: string; actions: ReactNode; muted?: boolean }) {
  return (
    <li className={[styles.row, muted && styles.muted].filter(Boolean).join(' ')}>
      <Icon name="document" size={20} className={styles.icon} />
      <span className={styles.text}>
        <span className={styles.name}>{file.name}</span>
        <small className={styles.meta}>{note ? `${describe(file)} · ${note}` : describe(file)}</small>
      </span>
      <span className={styles.actions}>{actions}</span>
    </li>
  );
}

function DropArea({ dragging, children, ...handlers }: { dragging: boolean; children: ReactNode } & ReturnType<typeof useDrop>['handlers']) {
  return (
    <section className={[styles.files, dragging && styles.dragging].filter(Boolean).join(' ')} aria-labelledby="files-title" {...handlers}>
      {children}
      {dragging && (
        <div className={styles.dropHere} aria-hidden="true">
          <Icon name="upload" size={22} />
          {t('files.dropHere')}
        </div>
      )}
    </section>
  );
}

/**
 * An item's files in the item view. Each one is downloaded and decrypted on this device; new ones
 * are encrypted here before they're uploaded. Changes apply at once.
 */
export function ItemFiles({ item, attachments, editable }: { item: Item; attachments: AttachmentService; editable: boolean }) {
  const toast = useToast();
  const files = attachmentsOf(item);
  const native = attachments.native;
  const [uploading, setUploading] = useState<string>();
  const [downloading, setDownloading] = useState<string>();
  const [removing, setRemoving] = useState<Attachment>();
  const drop = useDrop((picked) => void attach(picked), editable && !uploading && !native);

  async function attach(picked: (File | PickedFile)[]) {
    for (const file of picked) {
      setUploading(file.name);
      try {
        await addFile(attachments, item.id, file);
        toast({ message: t('files.attached', { name: file.name }), tone: 'success' });
      } catch (error) {
        toast({ message: t('files.attachFailed', { name: file.name, reason: errorMessage(error) }), tone: 'danger' });
      }
    }
    setUploading(undefined);
  }

  /** Downloads it in a browser; on a phone, decrypts it for the system viewer. */
  async function download(file: Attachment) {
    setDownloading(file.id);
    try {
      if (native) await native.open(item.id, file.id);
      else downloadBlob(await attachments.getAttachment(item.id, file.id), file.name);
    } catch (error) {
      toast({ message: errorMessage(error), tone: 'danger' });
    } finally {
      setDownloading(undefined);
    }
  }

  if (!files.length && !editable) return null;
  return (
    <DropArea dragging={drop.dragging} {...drop.handlers}>
      <div className={styles.head}>
        <h2 id="files-title" className={styles.title}>
          {t('files.title')}
        </h2>
        {editable && !native && <PickFiles label={t('files.attach')} onFiles={(picked) => void attach(picked)} disabled={Boolean(uploading)} />}
      </div>
      <ul className={styles.list} aria-busy={Boolean(uploading)}>
        {files.map((file) => (
          <FileRow
            key={file.id}
            file={file}
            note={downloading === file.id ? t('files.downloading') : file.pending ? t('files.waiting') : undefined}
            actions={
              <>
                <IconButton
                  size="sm"
                  icon={native ? 'eye' : 'download'}
                  label={t(native ? 'files.open' : 'files.download', { name: file.name })}
                  disabled={downloading === file.id}
                  onClick={() => void download(file)}
                />
                {editable && <IconButton size="sm" icon="trash" tone="danger" label={t('files.remove', { name: file.name })} onClick={() => setRemoving(file)} />}
              </>
            }
          />
        ))}
        {uploading && (
          <li className={[styles.row, styles.muted].join(' ')} role="status">
            <Spinner size={18} />
            <span className={styles.text}>
              <span className={styles.name}>{uploading}</span>
              <small className={styles.meta}>{t('files.uploading')}</small>
            </span>
          </li>
        )}
        {!files.length && !uploading && <li className={styles.empty}>{t('files.empty')}</li>}
      </ul>
      {editable && native && <PickNative native={native} onPicked={(picked) => void attach(picked)} disabled={Boolean(uploading)} />}
      {editable && <p className={styles.hint}>{t(native ? 'files.phoneHint' : 'files.dropHint')}</p>}
      <ConfirmDialog
        open={Boolean(removing)}
        title={t('files.removeTitle', { name: removing?.name ?? '' })}
        confirmLabel={t('files.removeConfirm')}
        onClose={() => setRemoving(undefined)}
        onConfirm={async () => {
          await attachments.removeAttachment(item.id, removing!.id);
          toast({ message: t('files.removed', { name: removing!.name }), tone: 'success' });
        }}
      >
        {t('files.removeBody')}
      </ConfirmDialog>
    </DropArea>
  );
}

/**
 * Someone else's files, read-only: an emergency contact's view of the grantor's item. `get`
 * downloads and decrypts one on this device.
 */
export function ReadOnlyFiles({ item, get }: { item: Item; get: (attachmentId: string) => Promise<Blob> }) {
  const toast = useToast();
  const files = attachmentsOf(item);
  const [downloading, setDownloading] = useState<string>();

  async function download(file: Attachment) {
    setDownloading(file.id);
    try {
      downloadBlob(await get(file.id), file.name);
    } catch (error) {
      toast({ message: errorMessage(error), tone: 'danger' });
    } finally {
      setDownloading(undefined);
    }
  }

  if (!files.length) return null;
  return (
    <section className={styles.files} aria-labelledby="files-title">
      <div className={styles.head}>
        <h2 id="files-title" className={styles.title}>
          {item.overview.type === 'document' ? t('files.documentTitle') : t('files.title')}
        </h2>
      </div>
      <ul className={styles.list}>
        {files.map((file) => (
          <FileRow
            key={file.id}
            file={file}
            note={downloading === file.id ? t('files.downloading') : undefined}
            actions={
              <IconButton
                size="sm"
                icon="download"
                label={t('files.download', { name: file.name })}
                disabled={downloading === file.id}
                onClick={() => void download(file)}
              />
            }
          />
        ))}
      </ul>
    </section>
  );
}

/** What the editor will do with files when it saves. */
export interface FileChanges {
  /** Files from the page's picker, or from the phone's (only described here). */
  add: (File | PickedFile)[];
  /** Ids of the item's attachments to remove. */
  remove: string[];
}

export const NO_FILE_CHANGES: FileChanges = { add: [], remove: [] };

export function hasFileChanges(changes: FileChanges): boolean {
  return changes.add.length > 0 || changes.remove.length > 0;
}

/** The editor's files: the item's own, plus files picked to attach or marked to remove on save. */
export function EditorFiles({
  original,
  changes,
  onChange,
  document,
  error,
}: {
  original: Item | undefined;
  changes: FileChanges;
  onChange: (changes: FileChanges) => void;
  /** A Document item: one file is the point of it. */
  document: boolean;
  error?: string;
}) {
  const native = useAttachments()?.native;
  const files = original ? attachmentsOf(original) : [];
  const add = (picked: (File | PickedFile)[]) => onChange({ ...changes, add: [...changes.add, ...picked] });
  const drop = useDrop(add, !native);
  // Picked files nobody saved are deleted when the editor closes (attached ones are gone already).
  const added = useRef(changes.add);
  added.current = changes.add;
  useEffect(() => () => void discard(native, added.current), [native]);
  const toggle = (id: string) => onChange({ ...changes, remove: changes.remove.includes(id) ? changes.remove.filter((r) => r !== id) : [...changes.remove, id] });
  return (
    <DropArea dragging={drop.dragging} {...drop.handlers}>
      <div className={styles.head}>
        <h2 id="files-title" className={styles.title}>
          {document ? t('files.documentTitle') : t('files.title')}
        </h2>
        {!native && <PickFiles label={document && !files.length && !changes.add.length ? t('files.attachOne') : t('files.attach')} onFiles={add} />}
      </div>
      {(files.length > 0 || changes.add.length > 0) && (
        <ul className={styles.list}>
          {files.map((file) => {
            const removed = changes.remove.includes(file.id);
            return (
              <FileRow
                key={file.id}
                file={file}
                muted={removed}
                note={removed ? t('files.willRemove') : undefined}
                actions={
                  removed ? (
                    <IconButton size="sm" icon="restore" label={t('files.keep', { name: file.name })} onClick={() => toggle(file.id)} />
                  ) : (
                    <IconButton size="sm" icon="trash" tone="danger" label={t('files.remove', { name: file.name })} onClick={() => toggle(file.id)} />
                  )
                }
              />
            );
          })}
          {changes.add.map((file, i) => (
            <FileRow
              key={`new-${i}`}
              file={file}
              note={t('files.pending')}
              actions={
                <IconButton
                  size="sm"
                  icon="close"
                  label={t('files.remove', { name: file.name })}
                  onClick={() => {
                    void discard(native, [file]);
                    onChange({ ...changes, add: changes.add.filter((_, j) => j !== i) });
                  }}
                />
              }
            />
          ))}
        </ul>
      )}
      {native && <PickNative native={native} onPicked={add} />}
      {error && (
        <p className={styles.error} role="alert">
          {error}
        </p>
      )}
      <p className={styles.hint}>{document ? t('files.documentHint') : t(native ? 'files.phoneHint' : 'files.dropHint')}</p>
    </DropArea>
  );
}

/**
 * Applies the editor's file changes to the saved item, one file at a time. Returns a message per
 * file that failed; the item itself is already saved.
 */
export async function applyFileChanges(attachments: AttachmentService, itemId: string, changes: FileChanges): Promise<string[]> {
  const failures: string[] = [];
  for (const id of changes.remove) {
    try {
      await attachments.removeAttachment(itemId, id);
    } catch (error) {
      failures.push(errorMessage(error));
    }
  }
  for (const file of changes.add) {
    try {
      await addFile(attachments, itemId, file);
    } catch (error) {
      failures.push(t('files.attachFailed', { name: file.name, reason: errorMessage(error) }));
    }
  }
  return failures;
}

/** A file from the page's picker goes up as a blob; one from the phone's, by its description. */
function addFile(attachments: AttachmentService, itemId: string, file: File | PickedFile): Promise<Item> {
  if (file instanceof Blob) return attachments.addAttachment(itemId, file, file.name);
  if (!attachments.native) throw new Error('a picked file without native files');
  return attachments.native.attachPicked(itemId, file);
}

/** Deletes the phone's copies of picked files that won't be attached. */
async function discard(native: NativeFiles | undefined, files: (File | PickedFile)[]): Promise<void> {
  const picked = files.filter((file): file is PickedFile => !(file instanceof Blob));
  if (native && picked.length) await native.discardPicked(picked).catch(() => undefined);
}

/** The service's attachments, when this host has them (a sync server account). */
export function useAttachments(): AttachmentService | undefined {
  return useService().attachments;
}
