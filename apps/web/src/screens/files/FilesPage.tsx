import { Button, Checkbox, Dialog, EmptyState, Icon, IconButton, Segmented, Spinner, Switch, TextField, useToast } from '@octapass/ui';
import { isVaultError, SAFE_ROOT, type FileMenuStatus, type FileRecipient, type FileResult, type FilesService, type FileTarget, type LocalFile, type SafeEntry, type SafeSummary } from '@octapass/vault-client';
import { useCallback, useEffect, useRef, useState } from 'react';
import { useService } from '../../app/ServiceContext';
import { formatBytes, t, type MessageKey } from '../../i18n';
import { errorMessage } from '../../lib/errors';
import { useAction } from '../../lib/useAction';
import { PageHeader } from '../PageHeader';
import { Row, Section } from '../settings/SettingsPage';
import settingsStyles from '../settings/SettingsPage.module.css';
import styles from './FilesPage.module.css';

type Mode = 'me' | 'people' | 'passphrase';

/** Tools → Files: encrypt and decrypt local files, Safes and the right-click menu (plan 16 §4). */
export function FilesPage() {
  const files = useService().files;
  if (!files) {
    return (
      <div className={settingsStyles.page}>
        <PageHeader title={t('fileTools.title')} />
      </div>
    );
  }
  return <Files files={files} />;
}

function Files({ files }: { files: FilesService }) {
  const [opened, setOpened] = useState<SafeSummary>();
  const [lockProblems, setLockProblems] = useState<string[]>([]);
  useEffect(() => {
    void files.lockProblems().then(setLockProblems, () => {});
  }, [files]);
  // Dropped files go to the Safe that's open, otherwise to the list to encrypt.
  const openedRef = useRef(opened);
  openedRef.current = opened;
  const [picked, setPicked] = useState<LocalFile[]>([]);
  const toast = useToast();
  const refreshSafes = useRef<() => void>(undefined);

  const add = useCallback(
    async (paths: string[]) => {
      if (paths.length === 0) return;
      try {
        const safe = openedRef.current;
        if (safe) {
          window.dispatchEvent(new CustomEvent('octapass-safe-add', { detail: paths }));
          return;
        }
        const described = await files.describe(paths);
        setPicked((current) => [...current, ...described.filter((one) => !current.some((known) => known.path === one.path))]);
      } catch (e) {
        toast({ message: errorMessage(e), tone: 'danger' });
      }
    },
    [files, toast],
  );

  useEffect(() => {
    const stops = [files.onDrop((paths) => void add(paths)), files.onRequest((request) => void add(request.paths))];
    return () => stops.forEach((stop) => void stop.then((run) => run()));
  }, [files, add]);

  return (
    <div className={settingsStyles.page}>
      <PageHeader title={t('fileTools.title')} subtitle={t('fileTools.subtitle')} />
      <div className={settingsStyles.body}>
        {lockProblems.length > 0 && (
          <div className={styles.caution} role="alert">
            <p>{t('fileTools.lockProblems')}</p>
            <ul>
              {lockProblems.map((problem) => (
                <li key={problem}>{problem}</li>
              ))}
            </ul>
          </div>
        )}
        {opened ? (
          <SafeBrowser files={files} safe={opened} onClose={() => { setOpened(undefined); refreshSafes.current?.(); }} />
        ) : (
          <>
            <Encrypting files={files} picked={picked} setPicked={setPicked} onChoose={add} />
            <Safes files={files} onOpen={setOpened} refresh={refreshSafes} />
            <ContextMenu files={files} />
            <FileKey files={files} />
          </>
        )}
      </div>
    </div>
  );
}

function Encrypting({ files, picked, setPicked, onChoose }: { files: FilesService; picked: LocalFile[]; setPicked: (list: LocalFile[]) => void; onChoose: (paths: string[]) => Promise<void> }) {
  const { busy, run } = useAction();
  const [mode, setMode] = useState<Mode>('me');
  const [people, setPeople] = useState<FileRecipient[]>([]);
  const [person, setPerson] = useState('');
  const [alsoMe, setAlsoMe] = useState(true);
  const [passphrase, setPassphrase] = useState('');
  const [again, setAgain] = useState('');
  const [armor, setArmor] = useState(false);
  const [shred, setShred] = useState(false);
  const [results, setResults] = useState<FileResult[]>([]);
  const [askPassphrase, setAskPassphrase] = useState(false);
  const [openPassphrase, setOpenPassphrase] = useState('');

  const plain = picked.filter((file) => !file.encrypted);
  const sealed = picked.filter((file) => file.encrypted);
  const storages = [...new Set(plain.map((file) => file.storage))];
  const mismatch = mode === 'passphrase' && again !== '' && passphrase !== again;
  const ready = plain.length > 0 && (mode === 'me' || (mode === 'people' && people.length > 0) || (mode === 'passphrase' && passphrase !== '' && passphrase === again));

  const addPerson = () =>
    run('person', async () => {
      const who = person.trim();
      if (!who) return;
      const found: FileRecipient = who.startsWith('age1') ? { email: who, recipient: who, fingerprint: '', verified: true } : await files.findRecipient(who);
      setPeople((current) => (current.some((one) => one.recipient === found.recipient) ? current : [...current, found]));
      setPerson('');
    });

  const encrypt = () =>
    run('encrypt', async () => {
      const target: FileTarget = mode === 'me' ? { kind: 'yourself' } : mode === 'people' ? { kind: 'people', to: people.map((one) => one.email), yourself: alsoMe } : { kind: 'passphrase', passphrase };
      const done = await files.encrypt({ paths: plain.map((file) => file.path), target, armor, shredOriginals: shred });
      setResults(done);
      setPicked(sealed);
      setPassphrase('');
      setAgain('');
    });

  const decrypt = () =>
    run('decrypt', async () => {
      try {
        const done = await files.decrypt({ paths: sealed.map((file) => file.path), passphrase: openPassphrase || undefined });
        setResults(done);
        setPicked(plain);
        setAskPassphrase(false);
        setOpenPassphrase('');
      } catch (e) {
        if (isVaultError(e) && e.code === 'passwordRequired') setAskPassphrase(true);
        else throw e;
      }
    });

  return (
    <section className={styles.tool} aria-label={t('fileTools.title')}>
      <div className={styles.drop}>
        <Icon name="upload" size={24} />
        <strong>{t('fileTools.dropTitle')}</strong>
        <p>{t('fileTools.dropHelp')}</p>
        <div className={styles.buttons}>
          <Button size="sm" variant="secondary" onClick={() => void files.choose(false).then(onChoose)}>
            {t('fileTools.chooseFiles')}
          </Button>
          <Button size="sm" variant="secondary" onClick={() => void files.choose(true).then(onChoose)}>
            {t('fileTools.chooseFolder')}
          </Button>
        </div>
      </div>

      {picked.length > 0 && (
        <ul className={styles.list}>
          {picked.map((file) => (
            <li key={file.path} className={styles.row}>
              <Icon name={file.encrypted ? 'lock' : file.folder ? 'vault' : 'document'} size={18} />
              <span className={styles.name} title={file.path}>
                {file.name}
              </span>
              <span className={styles.meta}>{file.folder ? '' : formatBytes(file.size)}</span>
              <span className={file.encrypted ? styles.sealed : styles.meta}>{t(file.encrypted ? 'fileTools.encryptedTag' : 'fileTools.plainTag')}</span>
              <IconButton icon="close" label={t('fileTools.remove', { name: file.name })} onClick={() => setPicked(picked.filter((one) => one.path !== file.path))} />
            </li>
          ))}
        </ul>
      )}

      {plain.length > 0 && (
        <div className={styles.form}>
          <Segmented
            block
            label={t('fileTools.who')}
            value={mode}
            onChange={setMode}
            options={[
              { value: 'me', label: t('fileTools.forMe') },
              { value: 'people', label: t('fileTools.forPeople') },
              { value: 'passphrase', label: t('fileTools.forPassphrase') },
            ]}
          />
          {mode === 'me' && <p className={styles.note}>{t('fileTools.forMeHelp')}</p>}
          {mode === 'people' && (
            <>
              <form
                className={styles.inline}
                onSubmit={(event) => {
                  event.preventDefault();
                  void addPerson();
                }}
              >
                <TextField label={t('fileTools.personField')} value={person} onChange={(event) => setPerson(event.target.value)} />
                <Button type="submit" size="sm" variant="secondary" disabled={!person.trim() || busy === 'person'}>
                  {t('fileTools.addPerson')}
                </Button>
              </form>
              {people.map((one) => (
                <div key={one.recipient} className={styles.person}>
                  <span className={styles.name}>{one.email}</span>
                  <IconButton icon="close" label={t('fileTools.remove', { name: one.email })} onClick={() => setPeople(people.filter((other) => other !== one))} />
                  {one.fingerprint && <p className={one.verified ? styles.note : styles.caution}>{one.verified ? t('fileTools.verified', { email: one.email }) : t('fileTools.unverified', { email: one.email, fingerprint: one.fingerprint })}</p>}
                </div>
              ))}
              <Checkbox checked={alsoMe} onChange={(event) => setAlsoMe(event.target.checked)} label={t('fileTools.alsoMe')} />
            </>
          )}
          {mode === 'passphrase' && (
            <>
              <TextField type="password" label={t('fileTools.passphrase')} value={passphrase} onChange={(event) => setPassphrase(event.target.value)} autoComplete="off" />
              <TextField type="password" label={t('fileTools.passphraseAgain')} value={again} onChange={(event) => setAgain(event.target.value)} autoComplete="off" error={mismatch ? t('fileTools.passphraseMismatch') : undefined} />
              <p className={styles.note}>{t('fileTools.passphraseHelp')}</p>
            </>
          )}
          <Switch label={t('fileTools.armor')} description={t('fileTools.armorHelp')} checked={armor} onChange={setArmor} />
          <Switch
            label={t('fileTools.shred')}
            description={t('fileTools.shredHelp')}
            checked={shred}
            onChange={setShred}
          />
          {shred && storages.map((storage) => (
            <p key={storage} className={storage === 'inPlaceDisk' ? styles.note : styles.caution}>
              {t(`fileTools.storage.${storage}` as MessageKey)}
            </p>
          ))}
          <Button onClick={() => void encrypt()} disabled={!ready} busy={busy === 'encrypt'}>
            {t('fileTools.encrypt')}
          </Button>
        </div>
      )}

      {sealed.length > 0 && (
        <div className={styles.form}>
          {askPassphrase && <TextField type="password" label={t('fileTools.decryptPassphrase')} value={openPassphrase} onChange={(event) => setOpenPassphrase(event.target.value)} autoComplete="off" />}
          <Button variant="secondary" onClick={() => void decrypt()} busy={busy === 'decrypt'} disabled={askPassphrase && !openPassphrase}>
            {t('fileTools.decrypt')}
          </Button>
        </div>
      )}

      {results.length > 0 && (
        <div className={styles.results} role="status">
          {results.map((result) => (
            <div key={result.output}>
              <p>{t('fileTools.result', { source: baseName(result.source), output: baseName(result.output) })}</p>
              {result.skipped.map((path) => (
                <p key={path} className={styles.note}>
                  {t('fileTools.skipped', { path })}
                </p>
              ))}
              {result.shredded === 'overwritten' && <p className={styles.note}>{t('fileTools.shredOverwritten')}</p>}
              {result.shredded === 'bestEffort' && result.storage && <p className={styles.caution}>{t('fileTools.shredBestEffort', { note: t(`fileTools.storage.${result.storage}` as MessageKey) })}</p>}
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

function baseName(path: string) {
  return path.split(/[\\/]/).pop() ?? path;
}

function Safes({ files, onOpen, refresh }: { files: FilesService; onOpen: (safe: SafeSummary) => void; refresh: React.RefObject<(() => void) | undefined> }) {
  const [safes, setSafes] = useState<SafeSummary[]>();
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState('');
  const [sync, setSync] = useState(false);
  const { busy, run } = useAction();

  const load = useCallback(() => {
    void files.listSafes().then(setSafes, () => setSafes([]));
  }, [files]);
  refresh.current = load;
  useEffect(load, [load]);

  const create = () =>
    run('create', async () => {
      await files.createSafe({ name: name.trim(), sync });
      setCreating(false);
      setName('');
      setSync(false);
      load();
    });

  return (
    <Section id="safes" title={t('fileTools.safesTitle')} description={t('fileTools.safesHelp')}>
      {safes === undefined ? (
        <div className={styles.padded}>
          <Spinner size={20} />
        </div>
      ) : safes.length === 0 ? (
        <EmptyState icon="lock" title={t('fileTools.noSafes')}>
          {t('fileTools.noSafesHelp')}
        </EmptyState>
      ) : (
        safes.map((safe) => (
          <Row key={safe.itemId} label={safe.name} description={t(safe.sync ? 'fileTools.synced' : 'fileTools.thisDevice')}>
            <Button size="sm" variant="secondary" onClick={() => onOpen(safe)}>
              {t('fileTools.open')}
            </Button>
          </Row>
        ))
      )}
      <div className={styles.padded}>
        <Button size="sm" icon="plus" onClick={() => setCreating(true)}>
          {t('fileTools.newSafe')}
        </Button>
      </div>
      <Dialog
        open={creating}
        onClose={() => setCreating(false)}
        title={t('fileTools.newSafe')}
        closeLabel={t('common.close')}
        footer={
          <Button onClick={() => void create()} disabled={!name.trim()} busy={busy === 'create'}>
            {t('fileTools.createSafe')}
          </Button>
        }
      >
        <div className={styles.form}>
          <TextField label={t('fileTools.safeName')} value={name} onChange={(event) => setName(event.target.value)} />
          <Switch label={t('fileTools.safeSync')} description={t('fileTools.safeSyncHelp')} checked={sync} onChange={setSync} />
        </div>
      </Dialog>
    </Section>
  );
}

function SafeBrowser({ files, safe, onClose }: { files: FilesService; safe: SafeSummary; onClose: () => void }) {
  const [path, setPath] = useState<{ id: string; name: string }[]>([]);
  const [entries, setEntries] = useState<SafeEntry[]>();
  const [naming, setNaming] = useState<{ kind: 'folder' } | { kind: 'rename'; entry: SafeEntry }>();
  const [name, setName] = useState('');
  const [deleting, setDeleting] = useState<SafeEntry>();
  const [deletingSafe, setDeletingSafe] = useState(false);
  const [typedName, setTypedName] = useState('');
  const [warnings, setWarnings] = useState(safe.warnings);
  const { busy, run } = useAction();
  const toast = useToast();
  const folder = path.at(-1)?.id ?? SAFE_ROOT;

  const load = useCallback(() => {
    void files.safeEntries({ itemId: safe.itemId, folder }).then(setEntries, (e: unknown) => {
      toast({ message: errorMessage(e), tone: 'danger' });
      setEntries([]);
    });
  }, [files, safe.itemId, folder, toast]);
  useEffect(load, [load]);
  // A synced Safe is fetched when it opens, which is how it first reaches a new device. Offline, the
  // copy on this device is what shows.
  useEffect(() => {
    if (!safe.sync) return;
    void files.syncSafe(safe.itemId).then(load, () => {});
  }, [files, safe.itemId, safe.sync, load]);
  // The page's drop handler sends what lands while a Safe is open here.
  useEffect(() => {
    const onAdd = (event: Event) => {
      const paths = (event as CustomEvent<string[]>).detail;
      void run('add', async () => {
        await files.safeAddFiles({ itemId: safe.itemId, folder, paths });
        load();
      });
    };
    window.addEventListener('octapass-safe-add', onAdd);
    return () => window.removeEventListener('octapass-safe-add', onAdd);
  }, [files, safe.itemId, folder, load, run]);

  const addFiles = () =>
    run('add', async () => {
      const paths = await files.choose(false);
      if (paths.length > 0) await files.safeAddFiles({ itemId: safe.itemId, folder, paths });
      load();
    });

  const lock = () =>
    run('lock', async () => {
      await files.safeLock(safe.itemId);
      onClose();
    });

  const sync = () =>
    run('sync', async () => {
      const report = await files.syncSafe(safe.itemId);
      for (const name of report.conflicts) toast({ message: t('fileTools.conflict', { name }), tone: 'neutral' });
      for (const name of report.tooBig) toast({ message: t('fileTools.tooBig', { name }), tone: 'danger' });
      const updated = (await files.listSafes()).find((one) => one.itemId === safe.itemId);
      if (updated) setWarnings(updated.warnings);
      load();
    }, t('fileTools.syncDone'));

  const finishNaming = () =>
    run('name', async () => {
      const value = name.trim();
      if (naming?.kind === 'folder') await files.safeCreateFolder({ itemId: safe.itemId, folder, name: value });
      else if (naming?.kind === 'rename') await files.safeRename({ itemId: safe.itemId, id: naming.entry.id, folder, name: value });
      setNaming(undefined);
      setName('');
      load();
    });

  const mount = () =>
    run('mount', async () => {
      const where = await files.safeMount(safe.itemId);
      toast({ message: t('fileTools.mounted', { path: where }), tone: 'success' });
    });

  const removeSafe = () =>
    run('deleteSafe', async () => {
      await files.deleteSafe(safe.itemId);
      setDeletingSafe(false);
      onClose();
    }, t('fileTools.safeDeleted', { name: safe.name }));

  const remove = () =>
    run('delete', async () => {
      if (deleting) await files.safeDelete({ itemId: safe.itemId, id: deleting.id });
      setDeleting(undefined);
      load();
    });

  return (
    <section className={styles.tool} aria-label={safe.name}>
      <div className={styles.browserHead}>
        <IconButton icon="chevronLeft" label={t('fileTools.back')} onClick={() => (path.length > 0 ? setPath(path.slice(0, -1)) : onClose())} />
        <h2 className={styles.safeName}>{[safe.name, ...path.map((part) => part.name)].join(' / ')}</h2>
        <div className={styles.buttons}>
          {safe.sync && (
            <Button size="sm" variant="secondary" icon="refresh" onClick={() => void sync()} busy={busy === 'sync'}>
              {t('fileTools.syncNow')}
            </Button>
          )}
          {safe.canMount && (
            <Button size="sm" variant="secondary" onClick={() => void mount()} busy={busy === 'mount'}>
              {t('fileTools.mount')}
            </Button>
          )}
          <Button size="sm" variant="secondary" icon="lock" onClick={() => void lock()} busy={busy === 'lock'}>
            {t('fileTools.lock')}
          </Button>
        </div>
      </div>
      {safe.inFinder && <p className={styles.note}>{t('fileTools.inFinder')}</p>}
      {warnings.map((warning, index) => (
        <p key={index} className={styles.caution}>
          {warning.kind === 'orphaned' ? t('fileTools.warnings.orphaned', { name: warning.name }) : t(`fileTools.warnings.${warning.kind}` as MessageKey)}
        </p>
      ))}
      <div className={styles.buttons}>
        <Button size="sm" icon="upload" onClick={() => void addFiles()} busy={busy === 'add'}>
          {t('fileTools.addFiles')}
        </Button>
        <Button size="sm" variant="secondary" icon="plus" onClick={() => setNaming({ kind: 'folder' })}>
          {t('fileTools.newFolder')}
        </Button>
        <Button size="sm" variant="secondary" icon="trash" onClick={() => setDeletingSafe(true)}>
          {t('fileTools.deleteSafe')}
        </Button>
      </div>
      {entries === undefined ? (
        <Spinner size={20} />
      ) : entries.length === 0 ? (
        <EmptyState icon="vault" title={t('fileTools.emptyFolder')}>
          {t('fileTools.emptyFolderHelp')}
        </EmptyState>
      ) : (
        <ul className={styles.list}>
          {entries.map((entry) => (
            <li key={entry.id} className={styles.row}>
              <Icon name={entry.folder ? 'vault' : 'document'} size={18} />
              {entry.folder ? (
                <button type="button" className={styles.link} onClick={() => setPath([...path, { id: entry.id, name: entry.name }])}>
                  {entry.name}
                </button>
              ) : (
                <span className={styles.name}>{entry.name}</span>
              )}
              <span className={styles.meta}>{entry.folder ? '' : formatBytes(entry.size)}</span>
              {!entry.folder && <IconButton icon="download" label={t('fileTools.saveCopy')} onClick={() => void run('save', () => files.safeSaveFile({ itemId: safe.itemId, id: entry.id }))} />}
              <IconButton
                icon="edit"
                label={t('fileTools.rename')}
                onClick={() => {
                  setName(entry.name);
                  setNaming({ kind: 'rename', entry });
                }}
              />
              <IconButton icon="trash" label={t('fileTools.delete')} onClick={() => setDeleting(entry)} />
            </li>
          ))}
        </ul>
      )}
      <Dialog
        open={naming !== undefined}
        onClose={() => setNaming(undefined)}
        title={naming?.kind === 'rename' ? t('fileTools.rename') : t('fileTools.newFolder')}
        closeLabel={t('common.close')}
        footer={
          <Button onClick={() => void finishNaming()} disabled={!name.trim()} busy={busy === 'name'}>
            {naming?.kind === 'rename' ? t('fileTools.rename') : t('fileTools.createFolder')}
          </Button>
        }
      >
        <TextField label={naming?.kind === 'rename' ? t('fileTools.newName') : t('fileTools.folderName')} value={name} onChange={(event) => setName(event.target.value)} />
      </Dialog>
      <Dialog
        open={deletingSafe}
        onClose={() => setDeletingSafe(false)}
        title={t('fileTools.deleteSafe')}
        description={t('fileTools.deleteSafeConfirm', { name: safe.name })}
        closeLabel={t('common.close')}
        footer={
          <Button variant="danger" onClick={() => void removeSafe()} disabled={typedName !== safe.name} busy={busy === 'deleteSafe'}>
            {t('fileTools.deleteSafe')}
          </Button>
        }
      >
        <TextField label={t('fileTools.typeSafeName', { name: safe.name })} value={typedName} onChange={(event) => setTypedName(event.target.value)} autoComplete="off" />
      </Dialog>
      <Dialog
        open={deleting !== undefined}
        onClose={() => setDeleting(undefined)}
        title={t('fileTools.delete')}
        description={deleting ? t('fileTools.deleteConfirm', { name: deleting.name }) : undefined}
        closeLabel={t('common.close')}
        footer={
          <Button variant="danger" onClick={() => void remove()} busy={busy === 'delete'}>
            {t('fileTools.delete')}
          </Button>
        }
      />
    </section>
  );
}

function ContextMenu({ files }: { files: FilesService }) {
  const [status, setStatus] = useState<FileMenuStatus[]>();
  const { run } = useAction();
  useEffect(() => {
    void files.menuStatus().then(setStatus, () => setStatus([]));
  }, [files]);
  if (!status?.length) return null;
  const on = status.every((one) => one.installed);
  // Finder and Dolphin are names; the other two have words that translate.
  const surfaces = status.map((one) => (one.surface === 'finder' ? 'Finder' : one.surface === 'dolphin' ? 'Dolphin' : t(`fileTools.surfaces.${one.surface}`))).join(', ');
  return (
    <Section id="context-menu" title={t('fileTools.menuTitle')} description={t('fileTools.menuHelp', { surfaces })}>
      <div className={styles.padded}>
        <Switch
          label={t('fileTools.menuOn')}
          checked={on}
          onChange={(wanted) =>
            void run(
              'menu',
              async () => {
                if (wanted) await files.installMenu(document.documentElement.lang);
                else await files.removeMenu();
                setStatus(await files.menuStatus());
              },
              t(wanted ? 'fileTools.menuAdded' : 'fileTools.menuRemoved'),
            )
          }
        />
      </div>
    </Section>
  );
}

function FileKey({ files }: { files: FilesService }) {
  const [recipient, setRecipient] = useState<string>();
  useEffect(() => {
    void files.ownRecipient().then(setRecipient, () => {});
  }, [files]);
  if (!recipient) return null;
  return (
    <Section id="file-key" title={t('fileTools.yourKey')} description={t('fileTools.yourKeyHelp')}>
      <div className={styles.padded}>
        <code className={styles.key}>{recipient}</code>
      </div>
    </Section>
  );
}
