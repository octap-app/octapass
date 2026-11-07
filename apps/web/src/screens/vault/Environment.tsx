import { Button, IconButton, Switch, TextArea, TextField, useToast } from '@octapass/ui';
import {
  KNOWN_STAGES,
  isProductionStage,
  mergeVariables,
  parseDotenv,
  writeEnvironment,
  type EnvironmentDetails,
  type EnvironmentVariable,
  type Item,
  type ItemDraft,
} from '@octapass/vault-client';
import { useRef, useState, type Dispatch, type SetStateAction } from 'react';
import { t, type MessageKey } from '../../i18n';
import { useCopy } from '../../lib/clipboard';
import { downloadBlob } from '../../lib/download';
import { useItems } from '../../lib/useItems';
import { Field, FieldList, SecretField } from './Fields';
import styles from './Environment.module.css';
import editorStyles from './ItemEditor.module.css';

export function stageLabel(stage: string | undefined): string {
  if (!stage) return t('env.sharedSet');
  return KNOWN_STAGES.includes(stage.toLowerCase() as (typeof KNOWN_STAGES)[number]) ? t(`env.stages.${stage.toLowerCase()}` as MessageKey) : stage;
}

function setDetails(setDraft: Dispatch<SetStateAction<ItemDraft>>) {
  return (patch: Partial<EnvironmentDetails>) => setDraft((draft) => ({ ...draft, details: { ...draft.details, ...patch } }));
}

/** The .env text of an environment's variables, for copying or downloading. */
export function environmentText(details: EnvironmentDetails): string {
  return writeEnvironment(details.variables, 'dotenv');
}

/** The variables as a table, with project and stage above. */
export function EnvironmentSection({
  draft,
  setDraft,
  fieldError,
}: {
  draft: ItemDraft;
  setDraft: Dispatch<SetStateAction<ItemDraft>>;
  fieldError: (path: string) => string | undefined;
}) {
  const details = draft.details as EnvironmentDetails;
  const set = setDetails(setDraft);
  const toast = useToast();
  const [pasting, setPasting] = useState(false);
  const [paste, setPaste] = useState('');
  const fileInput = useRef<HTMLInputElement>(null);
  const variables = details.variables ?? [];

  const change = (next: EnvironmentVariable[]) => set({ variables: next });
  const update = (index: number, patch: Partial<EnvironmentVariable>) => change(variables.map((one, i) => (i === index ? { ...one, ...patch } : one)));
  const remove = (index: number) => change(variables.filter((_, i) => i !== index));
  const move = (index: number, by: -1 | 1) => {
    const to = index + by;
    if (to < 0 || to >= variables.length) return;
    const next = [...variables];
    [next[index], next[to]] = [next[to]!, next[index]!];
    change(next);
  };

  function addPasted() {
    let parsed: EnvironmentVariable[];
    try {
      parsed = parseDotenv(paste).map(({ key, value }) => ({ key, value, concealed: true }));
    } catch (error) {
      toast({ message: t('env.importFailed', { reason: error instanceof Error ? error.message : String(error) }), tone: 'danger' });
      return;
    }
    change(mergeVariables(variables, parsed));
    setPaste('');
    setPasting(false);
    toast({ message: t('env.imported', { count: parsed.length }), tone: 'success' });
  }

  async function importFile(file: File | undefined) {
    if (!file) return;
    setPaste(await file.text());
    setPasting(true);
  }

  return (
    <>
      <fieldset className={editorStyles.section}>
        <legend className={editorStyles.sectionTitle}>{t('env.projectAndStage')}</legend>
        <div className={editorStyles.sectionBody}>
          <div className={editorStyles.pair}>
            <TextField
              label={t('env.project')}
              value={details.project ?? ''}
              onChange={(e) => set({ project: e.target.value.trim() || undefined })}
              placeholder={t('env.projectPlaceholder')}
              hint={t('env.projectHint')}
              error={fieldError('project')}
              spellCheck={false}
              dir="ltr"
            />
            <TextField
              label={t('env.stage')}
              value={details.stage ?? ''}
              onChange={(e) => set({ stage: e.target.value.trim() || undefined })}
              placeholder={t('env.stagePlaceholder')}
              hint={t('env.stageHint')}
              error={fieldError('stage')}
              spellCheck={false}
              dir="ltr"
            />
          </div>
          <p className={editorStyles.help}>{t('env.mergeHint')}</p>
        </div>
      </fieldset>

      <fieldset className={editorStyles.section}>
        <legend className={editorStyles.sectionTitle}>{t('env.variables')}</legend>
        <div className={editorStyles.sectionBody}>
          {variables.length === 0 && <p className={editorStyles.help}>{t('env.noVariables')}</p>}
          {variables.map((variable, i) => (
            <div key={i} className={styles.row}>
              <div className={styles.rowFields}>
                <TextField
                  label={t('env.key')}
                  hideLabel={i > 0}
                  mono
                  spellCheck={false}
                  dir="ltr"
                  placeholder="DATABASE_URL"
                  value={variable.key}
                  onChange={(e) => update(i, { key: e.target.value })}
                  error={fieldError(`variables.${i}.key`)}
                />
                <TextField
                  label={t('env.value')}
                  hideLabel
                  mono
                  type={variable.concealed ? 'password' : 'text'}
                  spellCheck={false}
                  autoComplete="off"
                  dir="ltr"
                  value={variable.value}
                  onChange={(e) => update(i, { value: e.target.value })}
                />
              </div>
              <div className={styles.rowActions}>
                <Switch label={t('env.concealed')} checked={variable.concealed} onChange={(concealed) => update(i, { concealed })} />
                <IconButton size="sm" icon="chevronDown" label={t('env.moveDown')} disabled={i === variables.length - 1} onClick={() => move(i, 1)} />
                <IconButton size="sm" icon="chevronDown" label={t('env.moveUp')} disabled={i === 0} className={styles.up} onClick={() => move(i, -1)} />
                <IconButton size="sm" icon="trash" tone="danger" label={t('env.removeVariable')} onClick={() => remove(i)} />
              </div>
              <TextField label={t('env.note')} hideLabel={i > 0} value={variable.note ?? ''} onChange={(e) => update(i, { note: e.target.value || undefined })} placeholder={t('env.notePlaceholder')} />
            </div>
          ))}
          <div className={editorStyles.inlineActions}>
            <Button variant="ghost" size="sm" icon="plus" onClick={() => change([...variables, { key: '', value: '', concealed: true }])}>
              {t('env.addVariable')}
            </Button>
            <Button variant="ghost" size="sm" onClick={() => setPasting((on) => !on)} aria-expanded={pasting}>
              {t('env.paste')}
            </Button>
            <Button variant="ghost" size="sm" icon="upload" onClick={() => fileInput.current?.click()}>
              {t('env.importFile')}
            </Button>
            <input ref={fileInput} type="file" accept=".env,text/plain" className="visually-hidden" onChange={(e) => void importFile(e.target.files?.[0])} />
          </div>
          {pasting && (
            <div className={editorStyles.bulk}>
              <TextArea label={t('env.paste')} mono rows={5} value={paste} onChange={(e) => setPaste(e.target.value)} hint={t('env.pasteHint')} />
              <Button size="sm" onClick={addPasted}>
                {t('env.addPasted')}
              </Button>
            </div>
          )}
        </div>
      </fieldset>

      <fieldset className={editorStyles.section}>
        <legend className={editorStyles.sectionTitle}>{t('fields.notes')}</legend>
        <div className={editorStyles.sectionBody}>
          <TextArea label={t('fields.notes')} hideLabel value={details.notes ?? ''} onChange={(e) => set({ notes: e.target.value || undefined })} />
        </div>
      </fieldset>
    </>
  );
}

/** An environment's variables, project and stage, with copy and download as .env. */
export function EnvironmentFields({ item }: { item: Item }) {
  const details = item.details as EnvironmentDetails;
  const copy = useCopy();
  const toast = useToast();
  const { items } = useItems({ type: 'environment' });
  const text = environmentText(details);
  const missing = missingKeys(
    details,
    (items ?? []).filter((one) => one.id !== item.id),
  );

  function copyDotenv() {
    void copy(text, t('env.copyDotenvWhat'));
  }

  function downloadDotenv() {
    const name = `${item.overview.title.replace(/[^\p{L}\p{N}._-]+/gu, '-').replace(/^-|-$/g, '') || 'environment'}.env`;
    downloadBlob(new Blob([text], { type: 'text/plain' }), name);
    toast({ message: t('env.downloaded', { name }), tone: 'success', icon: 'download' });
  }

  return (
    <>
      {(details.project || details.stage) && (
        <FieldList title={t('env.projectAndStage')}>
          <Field label={t('env.project')} value={details.project} secret={false} />
          <Field label={t('env.stage')} value={stageLabel(details.stage)} secret={false} copy={false} />
        </FieldList>
      )}
      <FieldList title={t('env.variables')}>
        {details.variables.length === 0 && <Field label={t('env.variables')} value={t('env.noVariables')} copy={false} />}
        {details.variables.map((variable) =>
          variable.concealed ? (
            <SecretField key={variable.key} label={variable.key} value={variable.value} what={variable.note ?? t('env.value')} />
          ) : (
            <Field key={variable.key} label={variable.key} value={variable.value} mono secret={false} />
          ),
        )}
      </FieldList>
      <div className={styles.actions}>
        <Button variant="secondary" size="sm" icon="copy" onClick={copyDotenv}>
          {t('env.copyDotenv')}
        </Button>
        <Button variant="secondary" size="sm" icon="download" onClick={downloadDotenv}>
          {t('env.downloadDotenv')}
        </Button>
      </div>
      {missing.length > 0 && <p className={styles.missing}>{t('env.missingInStage', { keys: missing.join(', ') })}</p>}
      {isProductionStage(details.stage) && <p className={styles.production}>{t('env.productionWarning')}</p>}
      {details.notes && (
        <FieldList title={t('fields.notes')}>
          <Field label={t('fields.notes')} value={details.notes} multiline secret />
        </FieldList>
      )}
    </>
  );
}

/** Variable keys that other stages of this project have but this environment doesn't. */
export function missingKeys(details: EnvironmentDetails, all: readonly { project?: string; stage?: string; variableKeys?: string[] }[]): string[] {
  return all
    .filter((one) => one.project === details.project && one.stage !== details.stage)
    .flatMap((one) => one.variableKeys ?? [])
    .filter((key, index, list) => !details.variables.some((variable) => variable.key === key) && list.indexOf(key) === index);
}
