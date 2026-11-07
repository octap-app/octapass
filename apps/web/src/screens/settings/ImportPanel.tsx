import { Button } from '@octapass/ui';
import { isVaultError, REVIEWED_IMPORTS, type ImportResult, type ImportReview, type ImportSource } from '@octapass/vault-client';
import { useEffect, useId, useRef, useState, type FormEvent } from 'react';
import { useService } from '../../app/ServiceContext';
import { Alert } from '../../components/Alert';
import { PasswordInput } from '../../components/PasswordInput';
import { t, type MessageKey } from '../../i18n';
import { errorMessage } from '../../lib/errors';
import { codeLinks, ImportReviewList, initialChoices, type CodeChoices } from '../vault/otp/ImportReviewList';
import { useLogins } from '../vault/otp/LoginPicker';
import styles from './SettingsPage.module.css';

interface Source {
  value: ImportSource;
  /** A product name (not translated), or a message key for descriptions. */
  name: string;
  accept: string;
  /** The file can be password-protected. */
  password?: boolean;
}

const CSV = '.csv,text/csv';
const JSON_FILE = '.json,application/json';

/** Every source the core imports, grouped as people look for them. */
export const SOURCE_GROUPS: { label: MessageKey; sources: Source[] }[] = [
  {
    label: 'import.groupOctaPass',
    sources: [
      { value: 'octapass', name: 'Octa Pass', accept: '.octapass,.json,application/json', password: true },
      { value: 'cxf', name: 'import.cxf', accept: JSON_FILE },
    ],
  },
  {
    label: 'import.groupManagers',
    sources: [
      { value: 'onepassword-1pux', name: '1Password (1PUX)', accept: '.1pux' },
      { value: 'onepassword-csv', name: '1Password (CSV)', accept: CSV },
      { value: 'avira', name: 'Avira', accept: CSV },
      { value: 'bitwarden-json', name: 'Bitwarden (JSON)', accept: JSON_FILE, password: true },
      { value: 'bitwarden-csv', name: 'Bitwarden (CSV)', accept: CSV },
      { value: 'dashlane', name: 'Dashlane', accept: `.zip,${JSON_FILE},${CSV}` },
      { value: 'enpass', name: 'Enpass', accept: JSON_FILE },
      { value: 'kaspersky', name: 'Kaspersky', accept: `.txt,${CSV}` },
      { value: 'keepass', name: 'KeePass, KeePassXC', accept: `.kdbx,.xml,${CSV}`, password: true },
      { value: 'keeper', name: 'Keeper', accept: `${CSV},${JSON_FILE}` },
      { value: 'lastpass-csv', name: 'LastPass', accept: CSV },
      { value: 'mcafee', name: 'McAfee True Key', accept: CSV },
      { value: 'nordpass', name: 'NordPass', accept: CSV },
      { value: 'norton', name: 'Norton', accept: CSV },
      { value: 'protonpass', name: 'Proton Pass', accept: `.zip,.pgp,${JSON_FILE},${CSV}`, password: true },
      { value: 'roboform', name: 'RoboForm', accept: CSV },
      { value: 'zoho-vault', name: 'Zoho Vault', accept: CSV },
    ],
  },
  {
    label: 'import.groupBrowsers',
    sources: [
      { value: 'chrome', name: 'import.chrome', accept: CSV },
      { value: 'firefox', name: 'Firefox', accept: CSV },
      { value: 'safari', name: 'import.safari', accept: CSV },
    ],
  },
  {
    label: 'import.groupAuthenticators',
    sources: [
      { value: 'aegis', name: 'Aegis', accept: JSON_FILE, password: true },
      { value: '2fas', name: '2FAS', accept: '.2fas,application/json', password: true },
      { value: 'andotp', name: 'andOTP', accept: `${JSON_FILE},.aes`, password: true },
      { value: 'ente-auth', name: 'Ente Auth', accept: `${JSON_FILE},.txt,text/plain`, password: true },
      { value: 'raivo', name: 'Raivo OTP', accept: `.zip,${JSON_FILE}`, password: true },
      { value: 'otpauth', name: 'import.otpauth', accept: '.txt,text/plain' },
    ],
  },
  { label: 'import.groupOther', sources: [{ value: 'generic-csv', name: 'import.generic', accept: CSV }] },
];

const SOURCES = SOURCE_GROUPS.flatMap((group) => group.sources);

function sourceName(source: Source): string {
  return source.name.startsWith('import.') ? t(source.name as MessageKey) : source.name;
}

export function ImportPanel() {
  const service = useService();
  const id = useId();
  const keyFileId = useId();
  const [source, setSource] = useState<ImportSource>('chrome');
  const [file, setFile] = useState<File>();
  const [password, setPassword] = useState('');
  const [keyFile, setKeyFile] = useState<File>();
  const [needsPassword, setNeedsPassword] = useState(false);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<ImportResult>();
  const [review, setReview] = useState<ImportReview>();
  const [choices, setChoices] = useState<CodeChoices>({});
  const [error, setError] = useState<string>();
  const logins = useLogins();
  const pending = useRef<string>(undefined);
  const input = useRef<HTMLInputElement>(null);
  const keyInput = useRef<HTMLInputElement>(null);
  const selected = SOURCES.find((s) => s.value === source)!;

  function choose(next: ImportSource) {
    setSource(next);
    setPassword('');
    setKeyFile(undefined);
    setNeedsPassword(false);
    setError(undefined);
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!file) {
      setError(t('import.chooseFile'));
      return;
    }
    setBusy(true);
    setError(undefined);
    setResult(undefined);
    try {
      const options = { password: password || undefined, keyFile };
      if (REVIEWED_IMPORTS.includes(source)) {
        // One-time codes: the user checks which login each one joins before anything is saved.
        const next = await service.reviewImport(source, file, options);
        if (next.codes.length > 0) {
          pending.current = next.id;
          setReview(next);
          setChoices(initialChoices(next));
        } else {
          setResult(await service.finishImport(next.id, []));
        }
      } else {
        setResult(await service.importFile(source, file, options));
      }
      setFile(undefined);
      setPassword('');
      setNeedsPassword(false);
      if (input.current) input.current.value = '';
    } catch (e) {
      if (isVaultError(e, 'importPasswordRequired')) setNeedsPassword(true);
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  // A review left open holds the parsed file in the vault's process.
  useEffect(
    () => () => {
      if (pending.current) void service.cancelImport(pending.current).catch(() => undefined);
    },
    [service],
  );

  async function finish() {
    if (!review) return;
    setBusy(true);
    setError(undefined);
    try {
      setResult(await service.finishImport(review.id, codeLinks(choices)));
      pending.current = undefined;
      setReview(undefined);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  function cancelReview() {
    if (pending.current) void service.cancelImport(pending.current).catch(() => undefined);
    pending.current = undefined;
    setReview(undefined);
  }

  if (review) {
    return (
      <div className={styles.import}>
        <p className={styles.rowDescription}>{t('otp.reviewHelp')}</p>
        {logins && <ImportReviewList review={review} logins={logins} choices={choices} onChange={setChoices} />}
        {review.warnings.length > 0 && (
          <Alert tone="warn">
            <ul className={styles.warnings}>
              {review.warnings.map((w, i) => (
                <li key={i}>{w}</li>
              ))}
            </ul>
          </Alert>
        )}
        {error && <Alert>{error}</Alert>}
        <div className={styles.reviewActions}>
          <Button variant="secondary" size="sm" disabled={busy} onClick={cancelReview}>
            {t('common.cancel')}
          </Button>
          <Button size="sm" icon="check" busy={busy} onClick={() => void finish()}>
            {t('otp.saveCodes', { count: review.codes.length + review.otherItems })}
          </Button>
        </div>
      </div>
    );
  }

  return (
    <form className={styles.import} onSubmit={submit}>
      <div className={styles.importFields}>
        <label className={styles.field}>
          <span>{t('import.from')}</span>
          <select className={styles.select} value={source} onChange={(e) => choose(e.target.value as ImportSource)}>
            {SOURCE_GROUPS.map((group) => (
              <optgroup key={group.label} label={t(group.label)}>
                {group.sources.map((s) => (
                  <option key={s.value} value={s.value}>
                    {sourceName(s)}
                  </option>
                ))}
              </optgroup>
            ))}
          </select>
        </label>
        <label className={styles.field} htmlFor={id}>
          <span>{t('import.file')}</span>
          <input id={id} ref={input} type="file" accept={selected.accept} className={styles.file} onChange={(e) => setFile(e.target.files?.[0])} />
        </label>
      </div>
      <p className={styles.rowDescription}>{t(`import.help.${source}` as MessageKey)}</p>
      {(selected.password || needsPassword) && (
        <div className={styles.importFields}>
          <PasswordInput
            label={t(source === 'octapass' ? 'import.exportPassword' : 'import.filePassword')}
            hint={needsPassword ? undefined : t('import.filePasswordHint')}
            autoComplete="off"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          {source === 'keepass' && (
            <label className={styles.field} htmlFor={keyFileId}>
              <span>{t('import.keyFile')}</span>
              <input id={keyFileId} ref={keyInput} type="file" className={styles.file} onChange={(e) => setKeyFile(e.target.files?.[0])} />
            </label>
          )}
        </div>
      )}
      {error && <Alert>{error}</Alert>}
      {result && (
        <Alert tone={result.imported > 0 || result.updated || result.unchanged ? 'success' : 'warn'}>
          <p>
            <strong>
              {result.updated || result.unchanged
                ? t('import.summary', { added: result.imported, updated: result.updated ?? 0, unchanged: result.unchanged ?? 0 })
                : t('import.done', { count: result.imported })}
            </strong> {result.skipped > 0 && t('import.skipped', { count: result.skipped })}{' '}
            {result.files ? t('import.files', { count: result.files }) : null}
          </p>
          {result.warnings.length > 0 && (
            <ul className={styles.warnings}>
              {result.warnings.map((w, i) => (
                <li key={i}>{w}</li>
              ))}
            </ul>
          )}
          <p>{t('import.deleteFile')}</p>
        </Alert>
      )}
      <div>
        <Button type="submit" variant="secondary" size="sm" icon="upload" busy={busy}>
          {t('import.action')}
        </Button>
      </div>
    </form>
  );
}
