import { Button, IconButton, TextArea, TextField, useToast } from '@octapass/ui';
import {
  addressQrText,
  CUSTOM_FIELD_KINDS,
  customKindIsPlain,
  emptyDraft,
  epcQrText,
  ITEM_FIELDS,
  isSecretKind,
  isSepaIban,
  isTableType,
  type BankAccountDetails,
  type CryptoWalletDetails,
  type CustomDetails,
  type CustomField,
  type CustomTemplateDetails,
  type ItemFieldSpec,
  type TableItemType,
  type TemplateField,
  type TypedField,
  type WalletAddress,
  type Item,
} from '@octapass/vault-client';
import { useEffect, useState } from 'react';
import { useService } from '../../app/ServiceContext';
import { QrCode } from '../../components/QrCode';
import { PasswordInput } from '../../components/PasswordInput';
import { formatDate, t, type MessageKey } from '../../i18n';
import { errorMessage } from '../../lib/errors';
import { useConfirmReveal } from '../../lib/identityGate';
import { useLive } from '../../lib/useItems';
import { CustomFieldsSection, Section, type SectionProps } from './EditorSections';
import { Field, FieldList, SecretField, TotpField } from './Fields';
import { PasswordHistory } from './ItemDetail';
import editorStyles from './ItemEditor.module.css';
import styles from './Wifi.module.css';

const QR_SECONDS = 60;
const fieldLabel = (key: string) => t(`itemFields.${key}` as MessageKey);

/** A choice's words, or what another app wrote when it's not one of ours. */
function choiceLabel(key: string, value: string): string {
  const label = t(`itemChoices.${key}.${value}` as MessageKey);
  return label.startsWith('itemChoices.') ? value : label;
}

const kindLabel = (kind: string) => choiceLabel('customKind', kind);

type Values = Record<string, string | undefined>;

function ChoiceInput({ spec, value, onChange }: { spec: ItemFieldSpec; value: string; onChange: (value: string) => void }) {
  const known = !value || spec.choices.includes(value);
  return (
    <label className={editorStyles.selectField}>
      <span>{fieldLabel(spec.key)}</span>
      <select value={value} onChange={(e) => onChange(e.target.value)}>
        <option value="" />
        {spec.choices.map((choice) => (
          <option key={choice} value={choice}>
            {choiceLabel(spec.key, choice)}
          </option>
        ))}
        {!known && <option value={value}>{value}</option>}
      </select>
    </label>
  );
}

/** A long secret stays hidden, also in the editor, until the person at the keyboard asks and is confirmed. */
function LongSecretInput({ label, value, error, onChange }: { label: string; value: string; error?: string; onChange: (value: string) => void }) {
  const [revealed, setRevealed] = useState(!value);
  const confirm = useConfirmReveal();
  async function reveal() {
    if (await confirm({ reason: t('identityGate.body') })) setRevealed(true);
  }
  if (!revealed) {
    return (
      <TextField
        label={label}
        value={'•'.repeat(16)}
        readOnly
        error={error}
        actions={<IconButton size="sm" icon="eye" label={t('typedItems.secretShow', { what: label })} onClick={() => void reveal()} />}
      />
    );
  }
  return (
    <TextArea
      label={label}
      value={value}
      mono
      dir="ltr"
      rows={3}
      autoComplete="off"
      autoCapitalize="off"
      autoCorrect="off"
      spellCheck={false}
      error={error}
      actions={<IconButton size="sm" icon="eyeOff" label={t('typedItems.secretHide', { what: label })} onClick={() => setRevealed(false)} />}
      onChange={(e) => onChange(e.target.value)}
    />
  );
}

function FieldInput({ spec, value, error, onChange }: { spec: ItemFieldSpec; value: string; error?: string; onChange: (value: string) => void }) {
  const label = fieldLabel(spec.key);
  switch (spec.kind) {
    case 'choice':
      return <ChoiceInput spec={spec} value={value} onChange={onChange} />;
    case 'secret':
      return <PasswordInput label={label} value={value} error={error} autoComplete="off" onChange={(e) => onChange(e.target.value)} />;
    case 'secretLong':
      return <LongSecretInput label={label} value={value} error={error} onChange={onChange} />;
    case 'date':
      return <TextField label={label} type="date" dir="ltr" value={value} error={error} autoComplete="off" onChange={(e) => onChange(e.target.value)} />;
    case 'email':
      return <TextField label={label} type="email" dir="ltr" value={value} error={error} autoComplete="off" onChange={(e) => onChange(e.target.value)} />;
    case 'port':
      return <TextField label={label} inputMode="numeric" dir="ltr" value={value} error={error} autoComplete="off" onChange={(e) => onChange(e.target.value)} />;
    case 'code':
      return <TextField label={label} mono dir="ltr" spellCheck={false} value={value} error={error} autoComplete="off" onChange={(e) => onChange(e.target.value)} />;
    default:
      return <TextField label={label} value={value} error={error} autoComplete="off" onChange={(e) => onChange(e.target.value)} />;
  }
}

/** The editor of every type in the field table. */
export function TableSection({ draft, setDraft, fieldError }: SectionProps) {
  const type = draft.overview.type as TableItemType;
  const details = draft.details as unknown as Values & { notes?: string; customFields?: CustomField[] };
  const set = (key: string, value: unknown) => setDraft((d) => ({ ...d, details: { ...d.details, [key]: value } }));
  return (
    <>
      <Section title={t(`types.${type}` as MessageKey)}>
        {ITEM_FIELDS[type].map((spec) => (
          <FieldInput key={spec.key} spec={spec} value={details[spec.key] ?? ''} error={fieldError(spec.key)} onChange={(value) => set(spec.key, value)} />
        ))}
      </Section>
      {type === 'cryptoWallet' && <AddressesSection addresses={(draft.details as CryptoWalletDetails).addresses} onChange={(list) => set('addresses', list)} fieldError={fieldError} />}
      <CustomFieldsSection fields={details.customFields} onChange={(list) => set('customFields', list)} />
      <Section title={t('fields.notes')}>
        <TextArea label={t('fields.notes')} hideLabel value={details.notes ?? ''} onChange={(e) => set('notes', e.target.value)} />
      </Section>
    </>
  );
}

function AddressesSection({ addresses, onChange, fieldError }: { addresses?: WalletAddress[]; onChange: (list: WalletAddress[]) => void; fieldError: SectionProps['fieldError'] }) {
  const list = addresses ?? [];
  const update = (index: number, patch: Partial<WalletAddress>) => onChange(list.map((entry, i) => (i === index ? { ...entry, ...patch } : entry)));
  return (
    <Section title={t('typedItems.addresses')}>
      {list.map((entry, i) => (
        <div key={i} className={editorStyles.customField}>
          <TextField label={t('typedItems.network')} hint={t('typedItems.networkHint')} dir="ltr" value={entry.network} autoComplete="off" onChange={(e) => update(i, { network: e.target.value })} />
          <TextField label={t('typedItems.address')} mono dir="ltr" spellCheck={false} value={entry.address} error={fieldError(`addresses.${i}`)} autoComplete="off" onChange={(e) => update(i, { address: e.target.value })} />
          <TextField label={t('typedItems.addressLabel')} value={entry.label ?? ''} autoComplete="off" onChange={(e) => update(i, { label: e.target.value })} />
          <div className={editorStyles.customFieldActions}>
            <IconButton size="sm" icon="trash" tone="danger" label={t('typedItems.removeAddress', { n: i + 1 })} onClick={() => onChange(list.filter((_, at) => at !== i))} />
          </div>
        </div>
      ))}
      <Button variant="ghost" size="sm" icon="plus" className={editorStyles.add} onClick={() => onChange([...list, { network: 'bitcoin', address: '' }])}>
        {t('typedItems.addAddress')}
      </Button>
    </Section>
  );
}

function KindSelect({ kind, onChange }: { kind: string; onChange: (kind: TemplateField['kind']) => void }) {
  const known = (CUSTOM_FIELD_KINDS as readonly string[]).includes(kind);
  return (
    <label className={editorStyles.selectField}>
      <span>{t('typedItems.fieldKind')}</span>
      <select value={kind} onChange={(e) => onChange(e.target.value as TemplateField['kind'])}>
        {CUSTOM_FIELD_KINDS.map((one) => (
          <option key={one} value={one}>
            {kindLabel(one)}
          </option>
        ))}
        {!known && <option value={kind}>{kind}</option>}
      </select>
    </label>
  );
}

/** The fields of a custom item, or of a template, which has no values. */
function FieldRows<T extends TemplateField>({ fields, values, onChange }: { fields: T[]; values: boolean; onChange: (list: T[]) => void }) {
  const update = (index: number, patch: Partial<TypedField>) => onChange(fields.map((field, i) => (i === index ? { ...field, ...patch } : field)));
  return (
    <Section title={t('typedItems.fields')}>
      {fields.map((field, i) => {
        const value = (field as unknown as TypedField).value ?? '';
        const change = (e: { target: { value: string } }) => update(i, { value: e.target.value });
        return (
          <div key={i} className={editorStyles.customField}>
            <TextField label={t('editor.fieldLabel')} value={field.label} autoComplete="off" onChange={(e) => update(i, { label: e.target.value })} />
            {values &&
              (!customKindIsPlain(field.kind) && field.kind !== 'multiline' ? (
                <PasswordInput label={t('editor.fieldValue')} value={value} autoComplete="off" onChange={change} />
              ) : field.kind === 'multiline' ? (
                <TextArea label={t('editor.fieldValue')} value={value} onChange={change} />
              ) : (
                <TextField label={t('editor.fieldValue')} type={field.kind === 'date' ? 'date' : field.kind === 'email' ? 'email' : field.kind === 'url' ? 'url' : field.kind === 'phone' ? 'tel' : 'text'} value={value} autoComplete="off" onChange={change} />
              ))}
            <div className={editorStyles.customFieldActions}>
              <KindSelect kind={field.kind} onChange={(kind) => update(i, { kind })} />
              <IconButton size="sm" icon="trash" tone="danger" label={t('editor.removeField', { label: field.label || t('editor.fieldN', { n: i + 1 }) })} onClick={() => onChange(fields.filter((_, at) => at !== i))} />
            </div>
          </div>
        );
      })}
      <Button variant="ghost" size="sm" icon="plus" className={editorStyles.add} onClick={() => onChange([...fields, (values ? { label: '', value: '', kind: 'text' } : { label: '', kind: 'text' }) as unknown as T])}>
        {t('editor.addField')}
      </Button>
    </Section>
  );
}

/** A template's fields as an item's, empty and ready to fill in. */
export function fieldsFromTemplate(template: Pick<CustomTemplateDetails, 'fields'>): TypedField[] {
  return template.fields.map(({ label, kind }) => ({ label, kind, value: '' }));
}

/** What a custom item saves as a template: labels and kinds, never its values. */
export function templateFields(fields: TypedField[]): TemplateField[] {
  return fields.filter((field) => field.label.trim()).map(({ label, kind }) => ({ label: label.trim(), kind }));
}

export function CustomSection({ draft, setDraft, isNew }: Omit<SectionProps, 'fieldError'> & { isNew: boolean }) {
  const service = useService();
  const toast = useToast();
  const details = draft.details as CustomDetails;
  const { data: templates } = useLive(() => service.listItems({ type: 'customTemplate' }), []);
  const patch = (next: Partial<CustomDetails>) => setDraft((d) => ({ ...d, details: { ...d.details, ...next } as CustomDetails }));

  async function chooseTemplate(id: string) {
    if (!id) return patch({ templateId: undefined, templateName: undefined });
    try {
      const template = await service.getItem(id);
      patch({ templateId: id, templateName: template.overview.title, fields: fieldsFromTemplate(template.details as CustomTemplateDetails) });
    } catch (e) {
      toast({ message: errorMessage(e), tone: 'danger' });
    }
  }

  async function saveAsTemplate() {
    const name = draft.overview.title.trim();
    if (!name) return toast({ message: t('typedItems.templateNeedsName'), tone: 'danger' });
    const template = emptyDraft('customTemplate', draft.vaultId);
    template.overview.title = name;
    (template.details as CustomTemplateDetails).fields = templateFields(details.fields);
    try {
      await service.saveItem(template);
      toast({ message: t('typedItems.templateSaved', { name }), tone: 'success' });
    } catch (e) {
      toast({ message: errorMessage(e), tone: 'danger' });
    }
  }

  return (
    <>
      {isNew && (templates?.length ?? 0) > 0 && (
        <Section title={t('typedItems.template')}>
          <label className={editorStyles.selectField}>
            <span>{t('typedItems.useTemplate')}</span>
            <select value={details.templateId ?? ''} onChange={(e) => void chooseTemplate(e.target.value)}>
              <option value="">{t('typedItems.noTemplate')}</option>
              {templates!.map((template) => (
                <option key={template.id} value={template.id}>
                  {template.title}
                </option>
              ))}
            </select>
          </label>
        </Section>
      )}
      <FieldRows fields={details.fields} values onChange={(fields) => patch({ fields })} />
      {details.fields.length > 0 && (
        <Button variant="secondary" size="sm" onClick={() => void saveAsTemplate()}>
          {t('typedItems.saveAsTemplate')}
        </Button>
      )}
      <Section title={t('fields.notes')}>
        <TextArea label={t('fields.notes')} hideLabel value={details.notes ?? ''} onChange={(e) => patch({ notes: e.target.value })} />
      </Section>
    </>
  );
}

export function TemplateSection({ draft, setDraft }: Omit<SectionProps, 'fieldError'>) {
  const details = draft.details as CustomTemplateDetails;
  return (
    <>
      <p>{t('typedItems.templateHelp')}</p>
      <FieldRows fields={details.fields} values={false} onChange={(fields) => setDraft((d) => ({ ...d, details: { ...d.details, fields } as CustomTemplateDetails }))} />
    </>
  );
}

function shownValue(spec: ItemFieldSpec, value: string): string {
  return spec.kind === 'choice' ? choiceLabel(spec.key, value) : spec.kind === 'date' ? formatDate(value) : value;
}

function TableField({ spec, value }: { spec: ItemFieldSpec; value?: string }) {
  const label = fieldLabel(spec.key);
  if (!value) return null;
  if (isSecretKind(spec.kind)) return <SecretField label={label} value={value} />;
  const shown = shownValue(spec, value);
  return <Field label={label} value={shown} secret={false} ltr={spec.kind === 'code' || spec.kind === 'port' || spec.kind === 'email'} mono={spec.kind === 'code'} copy={spec.kind !== 'choice'} />;
}

/** The detail view of every type in the field table. */
export function TableFields({ item }: { item: Item }) {
  const type = item.overview.type;
  if (!isTableType(type)) return null;
  const details = item.details as unknown as Values & { notes?: string; customFields?: CustomField[]; passwordHistory?: { password: string; changedAt: string }[] };
  const custom = details.customFields ?? [];
  return (
    <>
      <FieldList>
        {ITEM_FIELDS[type].map((spec) => (
          <TableField key={spec.key} spec={spec} value={details[spec.key]} />
        ))}
      </FieldList>
      {type === 'bankAccount' && <BankQr details={item.details as BankAccountDetails} />}
      {type === 'cryptoWallet' && <Addresses addresses={(item.details as CryptoWalletDetails).addresses ?? []} />}
      {custom.length > 0 && (
        <FieldList title={t('detail.moreFields')}>
          {custom.map((field, i) => (field.hidden ? <SecretField key={i} label={field.label} value={field.value} /> : <Field key={i} label={field.label} value={field.value} secret={false} />))}
        </FieldList>
      )}
      {details.notes && (
        <FieldList title={t('fields.notes')}>
          <Field label={t('fields.notes')} value={details.notes} multiline secret />
        </FieldList>
      )}
      {details.passwordHistory && details.passwordHistory.length > 0 && <PasswordHistory history={details.passwordHistory} />}
    </>
  );
}

/** Plan 01: every code hides itself after 60 seconds. */
function useShownBriefly(): [boolean, (shown: boolean) => void] {
  const [shown, setShown] = useState(false);
  useEffect(() => {
    if (!shown) return;
    const timer = setTimeout(() => setShown(false), QR_SECONDS * 1000);
    return () => clearTimeout(timer);
  }, [shown]);
  return [shown, setShown];
}

function BankQr({ details }: { details: BankAccountDetails }) {
  const [shown, setShown] = useShownBriefly();
  const [amount, setAmount] = useState('');
  const [reference, setReference] = useState('');
  if (!details.iban || !isSepaIban(details.iban)) return null;
  const name = details.accountHolder?.trim();
  if (!name) return <p className={styles.qr}>{t('typedItems.bankQrNeedsName')}</p>;
  const text = epcQrText({ name, iban: details.iban, bic: details.swift, amount, reference });
  return (
    <section className={styles.qr}>
      <Button variant="secondary" size="sm" icon={shown ? 'eyeOff' : 'eye'} aria-expanded={shown} onClick={() => setShown(!shown)}>
        {shown ? t('typedItems.bankQrHide') : t('typedItems.bankQrShow')}
      </Button>
      {shown && (
        <>
          <TextField label={t('typedItems.bankAmount')} inputMode="decimal" dir="ltr" value={amount} onChange={(e) => setAmount(e.target.value)} />
          <TextField label={t('typedItems.bankReference')} value={reference} onChange={(e) => setReference(e.target.value)} />
          {text ? <QrCode value={text} size={220} label={t('typedItems.bankQrLabel', { name })} /> : <p role="alert">{t('typedItems.bankQrInvalid')}</p>}
          <p>{t('typedItems.bankQrHelp')}</p>
        </>
      )}
    </section>
  );
}

function AddressRow({ entry }: { entry: WalletAddress }) {
  const [shown, setShown] = useShownBriefly();
  const qr = addressQrText(entry);
  const label = entry.label ? `${entry.label} (${entry.network})` : entry.network;
  return (
    <>
      <Field
        label={label}
        value={entry.address}
        what={t('typedItems.address')}
        secret={false}
        mono
        ltr
        actions={qr ? <IconButton size="sm" icon={shown ? 'eyeOff' : 'eye'} label={shown ? t('typedItems.hideQr') : t('typedItems.showQr')} aria-expanded={shown} onClick={() => setShown(!shown)} /> : undefined}
      />
      {shown && qr && (
        <div className={styles.qr}>
          <QrCode value={qr} size={200} label={t('typedItems.addressQrLabel', { network: entry.network })} />
          <p>{t('typedItems.addressQrHelp')}</p>
        </div>
      )}
    </>
  );
}

function Addresses({ addresses }: { addresses: WalletAddress[] }) {
  if (!addresses.length) return null;
  return (
    <FieldList title={t('typedItems.addresses')}>
      {addresses.map((entry, i) => (
        <AddressRow key={i} entry={entry} />
      ))}
    </FieldList>
  );
}

function CustomField_({ field }: { field: TypedField }) {
  if (!field.value) return null;
  if (field.kind === 'totp') return <TotpField secret={field.value} />;
  if (field.kind === 'multiline') return <Field label={field.label} value={field.value} multiline secret />;
  if (!customKindIsPlain(field.kind)) return <SecretField label={field.label} value={field.value} />;
  return <Field label={field.label} value={field.kind === 'date' ? formatDate(field.value) : field.value} secret={false} ltr={field.kind !== 'text'} />;
}

export function CustomFields({ details }: { details: CustomDetails }) {
  return (
    <>
      <FieldList>
        {details.templateName && <Field label={t('typedItems.template')} value={details.templateName} copy={false} />}
        {details.fields.map((field, i) => (
          <CustomField_ key={i} field={field} />
        ))}
      </FieldList>
      {details.notes && (
        <FieldList title={t('fields.notes')}>
          <Field label={t('fields.notes')} value={details.notes} multiline secret />
        </FieldList>
      )}
    </>
  );
}

export function TemplateFields({ details }: { details: CustomTemplateDetails }) {
  return (
    <FieldList title={t('typedItems.fields')}>
      {details.fields.map((field, i) => (
        <Field key={i} label={field.label} value={kindLabel(field.kind)} copy={false} />
      ))}
    </FieldList>
  );
}
