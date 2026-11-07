import { Button, Checkbox, Dialog, Icon, IconButton, Switch, TextArea, TextField, useToast } from '@octapass/ui';
import {
  DEFAULT_AUTO_TYPE_SEQUENCE,
  DEFAULT_PASSPHRASE_OPTIONS,
  DEFAULT_URL_MATCH_MODE,
  hasPassword,
  isEnterprise,
  URL_MATCH_MODES,
  WIFI_EAP_METHODS,
  WIFI_PHASE2,
  WIFI_SECURITIES,
  PASSWORD_AUTO_TYPE_SEQUENCE,
  type AutoTypeSettings,
  type BackupCode,
  type CardDetails,
  type CustomField,
  type DocumentDetails,
  type IdentityDetails,
  type Item,
  type ItemDraft,
  type LoginDetails,
  type MaskedAlias,
  type RecoveryInfo,
  type RecoverySource,
  type SecureNoteDetails,
  type SecurityQuestion,
  type TwoFactorMethod,
  type UrlMatchMode,
  type WifiDetails,
  type WifiEapMethod,
  type WifiPhase2,
  type WifiSecurity,
} from '@octapass/vault-client';
import { useState, type Dispatch, type ReactNode, type SetStateAction } from 'react';
import { useService } from '../../app/ServiceContext';
import { PasswordInput } from '../../components/PasswordInput';
import { StrengthHint } from '../../components/StrengthHint';
import { formatDate, t, type MessageKey } from '../../i18n';
import { providerName, useConnections, useCreateAlias } from '../../lib/maskedEmail';
import { useLive } from '../../lib/useItems';
import { GeneratorPanel } from '../generator/GeneratorPanel';
import styles from './ItemEditor.module.css';

export interface SectionProps {
  draft: ItemDraft;
  setDraft: Dispatch<SetStateAction<ItemDraft>>;
  fieldError: (path: string) => string | undefined;
}

export function Section({ title, children, aside }: { title: string; children: ReactNode; aside?: ReactNode }) {
  return (
    <fieldset className={styles.section}>
      <legend className={styles.sectionTitle}>{title}</legend>
      {aside}
      <div className={styles.sectionBody}>{children}</div>
    </fieldset>
  );
}

function useDetails<T>(setDraft: SectionProps['setDraft']) {
  return (patch: Partial<T>) => setDraft((d) => ({ ...d, details: { ...d.details, ...patch } }));
}

/** Edits a list in place: change, remove or append entries. */
function listOps<T>(list: T[] | undefined, commit: (next: T[]) => void) {
  const items = list ?? [];
  return {
    items,
    update: (index: number, patch: Partial<T>) => commit(items.map((item, i) => (i === index ? { ...item, ...patch } : item))),
    set: (index: number, value: T) => commit(items.map((item, i) => (i === index ? value : item))),
    remove: (index: number) => commit(items.filter((_, i) => i !== index)),
    add: (value: T) => commit([...items, value]),
  };
}

export function aliasSource(alias: MaskedAlias): RecoverySource {
  return { kind: 'alias', provider: alias.provider, aliasId: alias.aliasId };
}

/** "Use a masked email" for the login being edited: an alias for its first website. */
function useMaskedEmailFor(site: string | undefined): { available: boolean; busy: boolean; make: () => Promise<MaskedAlias | undefined> } {
  const connections = useConnections();
  const { create, busy } = useCreateAlias();
  const toast = useToast();
  const make = async () => {
    if (!site) {
      toast({ message: t('editor.maskedEmailNeedsSite'), tone: 'danger' });
      return undefined;
    }
    const alias = await create(site);
    if (alias) toast({ message: t('editor.maskedEmailMade', { email: alias.email }), tone: 'success' });
    return alias;
  };
  return { available: (connections?.length ?? 0) > 0, busy, make };
}

export function LoginSection({ draft, setDraft, fieldError }: SectionProps) {
  const service = useService();
  const details = draft.details as LoginDetails;
  const set = useDetails<LoginDetails>(setDraft);
  const [generatorOpen, setGeneratorOpen] = useState(false);
  const urls = listOps(draft.overview.urls?.length ? draft.overview.urls : [''], (next) => setDraft((d) => ({ ...d, overview: { ...d.overview, urls: next } })));
  const isLogin = draft.overview.type === 'login';
  const modeOf = (url: string): UrlMatchMode => draft.overview.urlMatch?.[url] ?? DEFAULT_URL_MATCH_MODE;
  const setMode = (url: string, mode: UrlMatchMode) => setDraft((d) => ({ ...d, overview: { ...d.overview, urlMatch: { ...d.overview.urlMatch, [url]: mode } } }));
  // Modes are keyed by the URL as written, so they follow it as it's typed.
  const setUrl = (i: number, value: string) =>
    setDraft((d) => {
      const list = d.overview.urls?.length ? d.overview.urls : [''];
      const old = list[i] ?? '';
      const { [old]: mode, ...urlMatch } = d.overview.urlMatch ?? {};
      return { ...d, overview: { ...d.overview, urls: list.map((one, at) => (at === i ? value : one)), urlMatch: mode ? { ...urlMatch, [value]: mode } : urlMatch } };
    });
  const site = urls.items.find((url) => url.trim() && modeOf(url) !== 'regex')?.trim();
  const masked = useMaskedEmailFor(site);

  // A new alias becomes the username and the recovery email, linked to its provider.
  const takeAlias = async () => {
    const alias = await masked.make();
    if (alias) set({ username: alias.email, recovery: { ...details.recovery, email: alias.email, emailSource: aliasSource(alias) } });
  };

  return (
    <>
      <Section title={t('editor.signIn')}>
        {isLogin && (
          <TextField
            label={t('fields.username')}
            autoComplete="off"
            spellCheck={false}
            dir="auto"
            value={details.username ?? ''}
            onChange={(e) => set({ username: e.target.value })}
            actions={masked.available && <IconButton size="sm" icon="mail" label={masked.busy ? t('editor.makingMaskedEmail') : t('editor.useMaskedEmail')} disabled={masked.busy} onClick={() => void takeAlias()} />}
          />
        )}
        <div className={styles.passwordGroup}>
          <PasswordInput
            label={t('fields.password')}
            autoComplete="new-password"
            value={details.password ?? ''}
            onChange={(e) => set({ password: e.target.value })}
            extraActions={<IconButton size="sm" icon="wand" label={t('editor.generate')} onClick={() => setGeneratorOpen(true)} />}
          />
          {details.password && <StrengthHint estimate={service.estimateStrength(details.password)} />}
        </div>
        {isLogin && (
          <TextField
            label={t('fields.totp')}
            mono
            spellCheck={false}
            autoComplete="off"
            value={details.totp ?? ''}
            onChange={(e) => set({ totp: e.target.value })}
            placeholder={t('editor.totpPlaceholder')}
            hint={t('editor.totpHint')}
            error={fieldError('totp')}
          />
        )}
        {/* The realm marks a login for a site's HTTP sign-in prompt: the extension fills only prompts that name it. */}
        {isLogin && (
          <TextField
            label={t('fields.httpRealm')}
            autoComplete="off"
            spellCheck={false}
            dir="auto"
            value={details.httpRealm ?? ''}
            onChange={(e) => set({ httpRealm: e.target.value || undefined })}
            hint={t('editor.httpRealmHint')}
          />
        )}
      </Section>

      {isLogin && (
        <Section title={t('editor.websites')}>
          {urls.items.map((url, i) => (
            <div key={i} className={styles.website}>
              <TextField
                label={i === 0 ? t('fields.website') : t('editor.websiteN', { n: i + 1 })}
                hideLabel={i > 0}
                type={modeOf(url) === 'regex' ? 'text' : 'url'}
                inputMode="url"
                spellCheck={false}
                placeholder={modeOf(url) === 'regex' ? '^https://[a-z]+\\.example\\.com/' : 'https://example.com'}
                value={url}
                onChange={(e) => setUrl(i, e.target.value)}
                error={fieldError(`urls.${i}`)}
                actions={urls.items.length > 1 && <IconButton size="sm" icon="close" label={t('editor.removeWebsite')} onClick={() => urls.remove(i)} />}
              />
              {url.trim() && (
                <label className={styles.selectField}>
                  <span>{t('editor.matchRule')}</span>
                  <select value={modeOf(url)} onChange={(e) => setMode(url, e.target.value as UrlMatchMode)}>
                    {URL_MATCH_MODES.map((mode) => (
                      <option key={mode} value={mode}>
                        {t(`editor.match.${mode}` as MessageKey)}
                      </option>
                    ))}
                  </select>
                </label>
              )}
              {url.trim() && (modeOf(url) === 'subdomains' || modeOf(url) === 'baseDomain') && <p className={styles.help}>{t(`editor.matchHelp.${modeOf(url) as 'subdomains' | 'baseDomain'}`)}</p>}
              {url.trim() && modeOf(url) === 'regex' && <p className={styles.help}>{t('editor.matchRegexWarning')}</p>}
            </div>
          ))}
          <Button variant="ghost" size="sm" icon="plus" className={styles.add} onClick={() => urls.add('')}>
            {t('editor.addWebsite')}
          </Button>
        </Section>
      )}

      {isLogin && <RecoverySection recovery={details.recovery} onChange={(recovery) => set({ recovery })} fieldError={fieldError} site={site} />}

      <CustomFieldsSection fields={details.customFields} onChange={(customFields) => set({ customFields })} />

      {service.autoType && (
        <AutoTypeSection
          settings={details.autoType}
          onChange={(autoType) => set({ autoType })}
          defaultSequence={isLogin ? DEFAULT_AUTO_TYPE_SEQUENCE : PASSWORD_AUTO_TYPE_SEQUENCE}
          shortcut={service.autoType.shortcut}
          fieldError={fieldError}
        />
      )}

      {details.passkeys && details.passkeys.length > 0 && (
        <Section title={t('detail.passkeys')}>
          <ul className={styles.readonlyList}>
            {details.passkeys.map((pk, i) => (
              <li key={i}>
                <Icon name="passkey" size={18} />
                <span>
                  {pk.rpId} · {pk.userName}
                  <small>{t('detail.passkeySaved', { date: formatDate(pk.createdAt) })}</small>
                </span>
              </li>
            ))}
          </ul>
          <p className={styles.help}>{t('editor.passkeysReadOnly')}</p>
        </Section>
      )}

      <Section title={t('fields.notes')}>
        <TextArea label={t('fields.notes')} hideLabel value={details.notes ?? ''} onChange={(e) => set({ notes: e.target.value })} />
      </Section>

      <Dialog open={generatorOpen} onClose={() => setGeneratorOpen(false)} closeLabel={t('common.close')} title={t('editor.generateTitle')} size="md">
        {generatorOpen && (
          <GeneratorPanel
            useLabel={t('editor.usePassword')}
            site={site}
            onUse={(password) => {
              set({ password });
              setGeneratorOpen(false);
            }}
          />
        )}
      </Dialog>
    </>
  );
}

const TWO_FACTOR: TwoFactorMethod[] = ['totp', 'passkey', 'key', 'sms', 'email', 'none'];

/** The vault's identities, for linking a recovery email or phone to one. */
function useIdentities(): Item[] {
  const service = useService();
  return (
    useLive(async () => {
      const summaries = await service.listItems({ type: 'identity' });
      return Promise.all(summaries.map((summary) => service.getItem(summary.id)));
    }, []).data ?? []
  );
}

/** Where a recovery email or phone came from, with a way to unlink it, or else the identities' values to pick from. */
function ContactLink({ source, value, options, identities, onPick, onUnlink }: {
  source?: RecoverySource;
  value?: string;
  options: { value: string; source: RecoverySource }[];
  identities: Item[];
  onPick: (value: string, source: RecoverySource) => void;
  onUnlink: () => void;
}) {
  if (source && value) {
    const identity = source.kind === 'identity' ? identities.find((i) => i.id === source.itemId) : undefined;
    const label = source.kind === 'alias' ? t('editor.linkedAlias', { provider: providerName(source.provider) }) : t('editor.linkedIdentity', { name: identity?.overview.title ?? t('types.identity') });
    return (
      <p className={styles.linked}>
        <Icon name={source.kind === 'alias' ? 'mail' : 'identity'} size={16} />
        <span>{label}</span>
        <Button variant="ghost" size="sm" onClick={onUnlink}>
          {t('editor.unlink')}
        </Button>
      </p>
    );
  }
  const choices = options.filter((option) => option.value !== value);
  if (choices.length === 0) return null;
  return (
    <div className={styles.linked}>
      <span>{t('editor.fromIdentities')}</span>
      {choices.map((option) => (
        <Button key={option.value} variant="ghost" size="sm" aria-label={t('editor.useContact', { value: option.value })} onClick={() => onPick(option.value, option.source)}>
          <bdi dir="ltr">{option.value}</bdi>
        </Button>
      ))}
    </div>
  );
}

function RecoverySection({ recovery = {}, onChange, fieldError, site }: { recovery?: RecoveryInfo; onChange: (r: RecoveryInfo) => void; fieldError: SectionProps['fieldError']; site: string | undefined }) {
  const service = useService();
  const codes = listOps<BackupCode>(recovery.backupCodes, (backupCodes) => onChange({ ...recovery, backupCodes }));
  const questions = listOps<SecurityQuestion>(recovery.securityQuestions, (securityQuestions) => onChange({ ...recovery, securityQuestions }));
  // Words, not symbols: a support agent may ask for the answer over the phone.
  const randomAnswer = () => service.generatePassword({ ...DEFAULT_PASSPHRASE_OPTIONS, separator: ' ' });
  const [bulk, setBulk] = useState(false);
  const [bulkText, setBulkText] = useState('');
  const identities = useIdentities();
  const masked = useMaskedEmailFor(site);
  const fromIdentities = (field: 'email' | 'phone') =>
    identities.flatMap((identity) => {
      const value = (identity.details as IdentityDetails)[field]?.trim();
      return value ? [{ value, source: { kind: 'identity' as const, itemId: identity.id } }] : [];
    });

  return (
    <Section title={t('detail.recovery')} aside={<p className={styles.help}>{t('editor.recoveryHelp')}</p>}>
      <label className={styles.selectField}>
        <span>{t('fields.twoFactorMethod')}</span>
        <select value={recovery.twoFactorMethod ?? ''} onChange={(e) => onChange({ ...recovery, twoFactorMethod: (e.target.value || undefined) as TwoFactorMethod | undefined })}>
          <option value="">{t('editor.notSet')}</option>
          {TWO_FACTOR.map((m) => (
            <option key={m} value={m}>
              {t(`twoFactor.${m}` as MessageKey)}
            </option>
          ))}
        </select>
      </label>
      <div className={styles.pair}>
        <div className={styles.contact}>
          <TextField
            label={t('fields.recoveryEmail')}
            type="email"
            value={recovery.email ?? ''}
            // Typing breaks the link: the value no longer comes from the identity or alias.
            onChange={(e) => onChange({ ...recovery, email: e.target.value, emailSource: undefined })}
            error={fieldError('recovery.email')}
            actions={
              masked.available && (
                <IconButton
                  size="sm"
                  icon="mail"
                  label={masked.busy ? t('editor.makingMaskedEmail') : t('editor.useMaskedEmail')}
                  disabled={masked.busy}
                  onClick={() => void masked.make().then((alias) => alias && onChange({ ...recovery, email: alias.email, emailSource: aliasSource(alias) }))}
                />
              )
            }
          />
          <ContactLink
            source={recovery.emailSource}
            value={recovery.email}
            options={fromIdentities('email')}
            identities={identities}
            onPick={(email, emailSource) => onChange({ ...recovery, email, emailSource })}
            onUnlink={() => onChange({ ...recovery, emailSource: undefined })}
          />
        </div>
        <div className={styles.contact}>
          <TextField label={t('fields.recoveryPhone')} type="tel" value={recovery.phone ?? ''} onChange={(e) => onChange({ ...recovery, phone: e.target.value, phoneSource: undefined })} />
          <ContactLink
            source={recovery.phoneSource}
            value={recovery.phone}
            options={fromIdentities('phone')}
            identities={identities}
            onPick={(phone, phoneSource) => onChange({ ...recovery, phone, phoneSource: phoneSource as Extract<RecoverySource, { kind: 'identity' }> })}
            onUnlink={() => onChange({ ...recovery, phoneSource: undefined })}
          />
        </div>
      </div>
      <div className={styles.subsection}>
        <p className={styles.subTitle}>{t('fields.backupCodes')}</p>
        {codes.items.length > 0 && (
          <ul className={styles.codeList}>
            {codes.items.map((code, i) => (
              <li key={i}>
                <TextField label={t('editor.codeN', { n: i + 1 })} hideLabel mono value={code.code} onChange={(e) => codes.update(i, { code: e.target.value })} />
                <Checkbox label={t('detail.codeUsed')} checked={code.used} onChange={(e) => codes.update(i, { used: e.target.checked })} />
                <IconButton size="sm" icon="close" label={t('editor.removeCode', { n: i + 1 })} onClick={() => codes.remove(i)} />
              </li>
            ))}
          </ul>
        )}
        {bulk ? (
          <div className={styles.bulk}>
            <TextArea label={t('editor.pasteCodes')} mono rows={4} value={bulkText} onChange={(e) => setBulkText(e.target.value)} hint={t('editor.pasteCodesHint')} />
            <Button
              size="sm"
              onClick={() => {
                const added = bulkText.split(/[\s,]+/).filter(Boolean).map((code) => ({ code, used: false }));
                onChange({ ...recovery, backupCodes: [...codes.items, ...added] });
                setBulkText('');
                setBulk(false);
              }}
            >
              {t('editor.addCodes')}
            </Button>
          </div>
        ) : (
          <div className={styles.inlineActions}>
            <Button variant="ghost" size="sm" icon="plus" onClick={() => codes.add({ code: '', used: false })}>
              {t('editor.addCode')}
            </Button>
            <Button variant="ghost" size="sm" onClick={() => setBulk(true)}>
              {t('editor.pasteCodes')}
            </Button>
          </div>
        )}
      </div>
      <div className={styles.subsection}>
        <p className={styles.subTitle}>{t('fields.securityQuestions')}</p>
        {questions.items.map((entry, i) => (
          <div key={i} className={styles.pair}>
            <TextField label={t('editor.question', { n: i + 1 })} dir="auto" autoComplete="off" value={entry.question} onChange={(e) => questions.update(i, { question: e.target.value })} />
            <PasswordInput
              label={t('fields.securityAnswer')}
              autoComplete="off"
              value={entry.answer}
              onChange={(e) => questions.update(i, { answer: e.target.value })}
              extraActions={
                <>
                  <IconButton size="sm" icon="wand" label={t('editor.randomAnswer')} onClick={() => questions.update(i, { answer: randomAnswer() })} />
                  <IconButton size="sm" icon="close" label={t('editor.removeQuestion', { n: i + 1 })} onClick={() => questions.remove(i)} />
                </>
              }
            />
          </div>
        ))}
        <div className={styles.inlineActions}>
          <Button variant="ghost" size="sm" icon="plus" onClick={() => questions.add({ question: '', answer: randomAnswer() })}>
            {t('editor.addQuestion')}
          </Button>
        </div>
        <p className={styles.help}>{t('editor.securityQuestionsHelp')}</p>
      </div>
    </Section>
  );
}

/** Desktop auto-type: what to type, and which windows besides the login's websites it may go to. */
function AutoTypeSection({
  settings,
  onChange,
  defaultSequence,
  shortcut,
  fieldError,
}: {
  settings?: AutoTypeSettings;
  onChange: (settings: AutoTypeSettings) => void;
  defaultSequence: string;
  shortcut: string;
  fieldError: SectionProps['fieldError'];
}) {
  const windows = listOps(settings?.windowTitles?.length ? settings.windowTitles : [''], (windowTitles) => onChange({ ...settings, windowTitles }));
  return (
    <Section title={t('editor.autoType')}>
      <p className={styles.help}>{t('editor.autoTypeHelp', { shortcut })}</p>
      <TextField
        label={t('editor.autoTypeSequence')}
        mono
        dir="ltr"
        spellCheck={false}
        autoComplete="off"
        placeholder={defaultSequence}
        value={settings?.sequence ?? ''}
        onChange={(e) => onChange({ ...settings, sequence: e.target.value })}
        hint={t('editor.autoTypeSequenceHint', { sequence: defaultSequence, fields: '{USERNAME} {PASSWORD} {TOTP} {TAB} {ENTER}', delay: '{DELAY 500}' })}
        error={fieldError('autoType.sequence')}
      />
      {windows.items.map((title, i) => (
        <TextField
          key={i}
          label={i === 0 ? t('editor.autoTypeWindow') : t('editor.autoTypeWindowN', { n: i + 1 })}
          hideLabel={i > 0}
          spellCheck={false}
          autoComplete="off"
          dir="auto"
          placeholder={i === 0 ? t('editor.autoTypeWindowPlaceholder') : undefined}
          hint={i === windows.items.length - 1 ? t('editor.autoTypeWindowHint') : undefined}
          value={title}
          onChange={(e) => windows.set(i, e.target.value)}
          actions={windows.items.length > 1 && <IconButton size="sm" icon="close" label={t('editor.removeAutoTypeWindow')} onClick={() => windows.remove(i)} />}
        />
      ))}
      <Button variant="ghost" size="sm" icon="plus" className={styles.add} onClick={() => windows.add('')}>
        {t('editor.addAutoTypeWindow')}
      </Button>
    </Section>
  );
}

export function CustomFieldsSection({ fields, onChange }: { fields?: CustomField[]; onChange: (f: CustomField[]) => void }) {
  const list = listOps(fields, onChange);
  return (
    <Section title={t('detail.moreFields')}>
      {list.items.map((field, i) => (
        <div key={i} className={styles.customField}>
          <TextField label={t('editor.fieldLabel')} value={field.label} onChange={(e) => list.update(i, { label: e.target.value })} />
          <TextField
            label={t('editor.fieldValue')}
            type={field.hidden ? 'password' : 'text'}
            mono={field.hidden}
            autoComplete="off"
            value={field.value}
            onChange={(e) => list.update(i, { value: e.target.value })}
          />
          <div className={styles.customFieldActions}>
            <Checkbox label={t('editor.fieldHidden')} checked={field.hidden} onChange={(e) => list.update(i, { hidden: e.target.checked })} />
            <IconButton size="sm" icon="trash" tone="danger" label={t('editor.removeField', { label: field.label || t('editor.fieldN', { n: i + 1 }) })} onClick={() => list.remove(i)} />
          </div>
        </div>
      ))}
      <Button variant="ghost" size="sm" icon="plus" className={styles.add} onClick={() => list.add({ label: '', value: '', hidden: false })}>
        {t('editor.addField')}
      </Button>
    </Section>
  );
}

export function CardSection({ draft, setDraft, fieldError }: SectionProps) {
  const details = draft.details as CardDetails;
  const set = useDetails<CardDetails>(setDraft);
  return (
    <>
      <Section title={t('editor.cardDetails')}>
        <TextField label={t('fields.cardholder')} autoComplete="off" value={details.cardholder ?? ''} onChange={(e) => set({ cardholder: e.target.value })} />
        <PasswordInput label={t('fields.cardNumber')} inputMode="numeric" autoComplete="off" value={details.number ?? ''} onChange={(e) => set({ number: e.target.value })} error={fieldError('number')} />
        <div className={styles.triple}>
          <TextField label={t('fields.expiry')} inputMode="numeric" placeholder={t('editor.expiryPlaceholder')} maxLength={5} value={details.expiry ?? ''} onChange={(e) => set({ expiry: e.target.value })} error={fieldError('expiry')} />
          <PasswordInput label={t('fields.cvv')} inputMode="numeric" autoComplete="off" maxLength={4} value={details.cvv ?? ''} onChange={(e) => set({ cvv: e.target.value })} />
          <PasswordInput label={t('fields.pin')} inputMode="numeric" autoComplete="off" maxLength={12} value={details.pin ?? ''} onChange={(e) => set({ pin: e.target.value })} />
        </div>
        <TextField label={t('fields.brand')} value={details.brand ?? ''} onChange={(e) => set({ brand: e.target.value })} hint={t('editor.brandHint')} />
      </Section>
      <Section title={t('fields.notes')}>
        <TextArea label={t('fields.notes')} hideLabel value={details.notes ?? ''} onChange={(e) => set({ notes: e.target.value })} />
      </Section>
    </>
  );
}

export function IdentitySection({ draft, setDraft, fieldError }: SectionProps) {
  const details = draft.details as IdentityDetails;
  const set = useDetails<IdentityDetails>(setDraft);
  const address = details.address ?? {};
  const setAddress = (patch: Partial<NonNullable<IdentityDetails['address']>>) => set({ address: { ...address, ...patch } });
  return (
    <>
      <Section title={t('editor.person')}>
        <div className={styles.pair}>
          <TextField label={t('fields.firstName')} autoComplete="off" value={details.firstName ?? ''} onChange={(e) => set({ firstName: e.target.value })} />
          <TextField label={t('fields.lastName')} autoComplete="off" value={details.lastName ?? ''} onChange={(e) => set({ lastName: e.target.value })} />
        </div>
        <div className={styles.pair}>
          <TextField label={t('fields.email')} type="email" autoComplete="off" value={details.email ?? ''} onChange={(e) => set({ email: e.target.value })} error={fieldError('email')} />
          <TextField label={t('fields.phone')} type="tel" autoComplete="off" value={details.phone ?? ''} onChange={(e) => set({ phone: e.target.value })} />
        </div>
        <TextField label={t('fields.birthDate')} type="date" value={details.birthDate ?? ''} onChange={(e) => set({ birthDate: e.target.value })} />
      </Section>
      <Section title={t('fields.address')}>
        <TextField label={t('fields.addressLine1')} autoComplete="off" value={address.line1 ?? ''} onChange={(e) => setAddress({ line1: e.target.value })} />
        <TextField label={t('fields.addressLine2')} autoComplete="off" value={address.line2 ?? ''} onChange={(e) => setAddress({ line2: e.target.value })} />
        <div className={styles.pair}>
          <TextField label={t('fields.city')} autoComplete="off" value={address.city ?? ''} onChange={(e) => setAddress({ city: e.target.value })} />
          <TextField label={t('fields.region')} autoComplete="off" value={address.region ?? ''} onChange={(e) => setAddress({ region: e.target.value })} />
        </div>
        <div className={styles.pair}>
          <TextField label={t('fields.postalCode')} autoComplete="off" value={address.postalCode ?? ''} onChange={(e) => setAddress({ postalCode: e.target.value })} />
          <TextField label={t('fields.country')} autoComplete="off" value={address.country ?? ''} onChange={(e) => setAddress({ country: e.target.value })} />
        </div>
      </Section>
      <Section title={t('fields.notes')}>
        <TextArea label={t('fields.notes')} hideLabel value={details.notes ?? ''} onChange={(e) => set({ notes: e.target.value })} />
      </Section>
    </>
  );
}

export function NoteSection({ draft, setDraft }: Omit<SectionProps, 'fieldError'>) {
  const details = draft.details as SecureNoteDetails;
  return (
    <Section title={t('fields.note')}>
      <TextArea label={t('fields.note')} hideLabel rows={10} value={details.notes} onChange={(e) => setDraft((d) => ({ ...d, details: { ...d.details, notes: e.target.value } }))} />
    </Section>
  );
}

export function DocumentSection({ draft, setDraft }: Omit<SectionProps, 'fieldError'>) {
  const details = draft.details as DocumentDetails;
  return (
    <Section title={t('fields.notes')}>
      <TextArea label={t('fields.notes')} hideLabel rows={5} value={details.notes ?? ''} onChange={(e) => setDraft((d) => ({ ...d, details: { ...d.details, notes: e.target.value } }))} />
    </Section>
  );
}

const PERSONAL: WifiSecurity[] = WIFI_SECURITIES.filter((security) => hasPassword(security) && !isEnterprise(security));
const ENTERPRISE: WifiSecurity[] = WIFI_SECURITIES.filter(isEnterprise);

export function WifiSection({ draft, setDraft, fieldError }: SectionProps) {
  const service = useService();
  const details = draft.details as WifiDetails;
  const set = useDetails<WifiDetails>(setDraft);
  const [generatorOpen, setGeneratorOpen] = useState(false);
  const enterprise = isEnterprise(details.security);
  const shared = hasPassword(details.security) && !enterprise;
  const option = (security: WifiSecurity) => (
    <option key={security} value={security}>
      {t(`wifi.securities.${security}` as MessageKey)}
    </option>
  );

  return (
    <>
      <Section title={t('wifi.network')}>
        <TextField
          label={t('wifi.ssid')}
          autoComplete="off"
          spellCheck={false}
          autoCapitalize="off"
          dir="auto"
          value={details.ssid}
          onChange={(e) => set({ ssid: e.target.value })}
          hint={t('wifi.ssidHint')}
          error={fieldError('ssid')}
          required
        />
        <label className={styles.selectField}>
          <span>{t('wifi.security')}</span>
          <select value={details.security} onChange={(e) => set({ security: e.target.value as WifiSecurity })}>
            <optgroup label={t('wifi.personal')}>{PERSONAL.map(option)}</optgroup>
            <optgroup label={t('wifi.enterpriseGroup')}>{ENTERPRISE.map(option)}</optgroup>
            <optgroup label={t('wifi.other')}>{option('wep')}{option('open')}</optgroup>
          </select>
        </label>
        <p className={styles.help}>{details.security === 'open' ? t('wifi.openHint') : t('wifi.securityHint')}</p>
        {shared && (
          <div className={styles.passwordGroup}>
            <PasswordInput
              label={t('fields.password')}
              autoComplete="new-password"
              value={details.password ?? ''}
              onChange={(e) => set({ password: e.target.value })}
              hint={details.security === 'wep' ? t('wifi.wepHint') : t('wifi.wpaHint')}
              error={fieldError('password')}
              extraActions={details.security !== 'wep' && <IconButton size="sm" icon="wand" label={t('editor.generate')} onClick={() => setGeneratorOpen(true)} />}
            />
            {details.password && details.security !== 'wep' && <StrengthHint estimate={service.estimateStrength(details.password)} />}
          </div>
        )}
        <Switch label={t('wifi.hidden')} description={t('wifi.hiddenHint')} checked={Boolean(details.hidden)} onChange={(hidden) => set({ hidden })} />
      </Section>

      {enterprise && (
        <Section title={t('wifi.enterprise')} aside={<p className={styles.help}>{t('wifi.enterpriseHelp')}</p>}>
          <div className={styles.pair}>
            <label className={styles.selectField}>
              <span>{t('wifi.eapMethod')}</span>
              <select value={details.eapMethod ?? ''} onChange={(e) => set({ eapMethod: (e.target.value || undefined) as WifiEapMethod | undefined })}>
                <option value="">{t('editor.notSet')}</option>
                {WIFI_EAP_METHODS.map((method) => (
                  <option key={method} value={method}>
                    {t(`wifi.eapMethods.${method}` as MessageKey)}
                  </option>
                ))}
              </select>
            </label>
            {(details.eapMethod === 'peap' || details.eapMethod === 'ttls') && (
              <label className={styles.selectField}>
                <span>{t('wifi.phase2')}</span>
                <select value={details.phase2 ?? ''} onChange={(e) => set({ phase2: (e.target.value || undefined) as WifiPhase2 | undefined })}>
                  <option value="">{t('editor.notSet')}</option>
                  {WIFI_PHASE2.map((method) => (
                    <option key={method} value={method}>
                      {t(`wifi.phase2s.${method}` as MessageKey)}
                    </option>
                  ))}
                </select>
              </label>
            )}
          </div>
          <TextField label={t('fields.username')} autoComplete="off" spellCheck={false} autoCapitalize="off" dir="auto" value={details.username ?? ''} onChange={(e) => set({ username: e.target.value })} />
          {details.eapMethod !== 'tls' && <PasswordInput label={t('fields.password')} autoComplete="off" value={details.password ?? ''} onChange={(e) => set({ password: e.target.value })} />}
          <TextField label={t('wifi.identity')} autoComplete="off" spellCheck={false} autoCapitalize="off" dir="auto" value={details.identity ?? ''} onChange={(e) => set({ identity: e.target.value })} hint={t('wifi.identityHint')} />
          <TextField label={t('wifi.serverDomain')} autoComplete="off" spellCheck={false} autoCapitalize="off" dir="ltr" inputMode="url" value={details.serverDomain ?? ''} onChange={(e) => set({ serverDomain: e.target.value })} hint={t('wifi.serverDomainHint')} />
          <TextArea label={t('wifi.caCertificate')} mono rows={4} spellCheck={false} dir="ltr" value={details.caCertificate ?? ''} onChange={(e) => set({ caCertificate: e.target.value })} hint={t('wifi.caCertificateHint')} />
        </Section>
      )}

      <Section title={t('wifi.about')}>
        <Switch label={t('wifi.captivePortal')} description={t('wifi.captivePortalHint')} checked={Boolean(details.captivePortal)} onChange={(captivePortal) => set({ captivePortal })} />
        <Switch label={t('wifi.managed')} description={t('wifi.managedHint')} checked={Boolean(details.managed)} onChange={(managed) => set({ managed })} />
        <Switch label={t('wifi.hotspot')} description={t('wifi.hotspotHint')} checked={Boolean(details.hotspot)} onChange={(hotspot) => set({ hotspot })} />
      </Section>

      <CustomFieldsSection fields={details.customFields} onChange={(customFields) => set({ customFields })} />

      <Section title={t('fields.notes')}>
        <TextArea label={t('fields.notes')} hideLabel value={details.notes ?? ''} onChange={(e) => set({ notes: e.target.value })} />
      </Section>

      <Dialog open={generatorOpen} onClose={() => setGeneratorOpen(false)} closeLabel={t('common.close')} title={t('editor.generateTitle')} size="md">
        {generatorOpen && (
          <GeneratorPanel
            useLabel={t('editor.usePassword')}
            onUse={(password) => {
              set({ password });
              setGeneratorOpen(false);
            }}
          />
        )}
      </Dialog>
    </>
  );
}
