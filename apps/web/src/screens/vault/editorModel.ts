import {
  checkAutoTypeSequence,
  DEFAULT_URL_MATCH_MODE,
  hasPassword,
  isEnterprise,
  isLoginLike,
  isSecretKind,
  isTableType,
  ITEM_FIELDS,
  SUBTITLE_KEYS,
  validateItemFields,
  isValidEmail,
  isValidTotp,
  type CardDetails,
  type CryptoWalletDetails,
  type CustomDetails,
  type CustomField,
  type CustomTemplateDetails,
  type EnvironmentDetails,
  type IdentityDetails,
  type Item,
  type ItemDraft,
  type ItemType,
  type LoginDetails,
  type SshKeyDetails,
  type TableItemType,
  type WifiDetails,
  uniqueWebsites,
  validEnvironmentKey,
} from '@octapass/vault-client';
import type { MessageKey } from '../../i18n';

export type EditorErrors = Partial<Record<string, MessageKey>>;

export function detectCardBrand(number: string): string | undefined {
  const digits = number.replace(/\D/g, '');
  if (/^4/.test(digits)) return 'Visa';
  if (/^(5[1-5]|2[2-7])/.test(digits)) return 'Mastercard';
  if (/^3[47]/.test(digits)) return 'American Express';
  if (/^6(011|5)/.test(digits)) return 'Discover';
  return undefined;
}

function looksLikeUrl(value: string): boolean {
  try {
    const url = new URL(/^[a-z][a-z\d+.-]*:\/\//i.test(value) ? value : `https://${value}`);
    return url.hostname.includes('.') || url.hostname === 'localhost';
  } catch {
    return false;
  }
}

/** A close check: the core's regular expressions are a little narrower, and one it can't read matches nothing. */
function isRegex(value: string): boolean {
  try {
    new RegExp(value);
    return true;
  } catch {
    return false;
  }
}

/** Field errors keyed by path ("title", "urls.1", "recovery.email"). Empty when the draft can be saved. */
export function validateDraft(draft: ItemDraft): EditorErrors {
  const errors: EditorErrors = {};
  // A network without a title is named after itself.
  const named = (draft.overview.type === 'wifi' && (draft.details as WifiDetails).ssid.trim()) || (draft.overview.type === 'sshKey' && (draft.details as SshKeyDetails).comment?.trim());
  if (!draft.overview.title.trim() && !named) errors.title = 'validation.titleRequired';

  if (isLoginLike(draft.overview.type)) {
    const details = draft.details as LoginDetails;
    draft.overview.urls?.forEach((url, i) => {
      if (!url.trim()) return;
      if (draft.overview.urlMatch?.[url] === 'regex') {
        if (!isRegex(url.trim())) errors[`urls.${i}`] = 'validation.regex';
      } else if (!looksLikeUrl(url.trim())) errors[`urls.${i}`] = 'validation.url';
    });
    if (details.totp?.trim() && !isValidTotp(details.totp.trim())) errors.totp = 'validation.totp';
    if (details.recovery?.email?.trim() && !isValidEmail(details.recovery.email.trim())) errors['recovery.email'] = 'validation.email';
    if (details.autoType?.sequence && checkAutoTypeSequence(details.autoType.sequence)) errors['autoType.sequence'] = 'validation.autoTypeSequence';
  }
  if (draft.overview.type === 'card') {
    const details = draft.details as CardDetails;
    if (details.expiry?.trim() && !/^(0[1-9]|1[0-2])\/\d{2}$/.test(details.expiry.trim())) errors.expiry = 'validation.expiry';
    if (details.number?.trim() && !/^[\d\s-]{12,23}$/.test(details.number.trim())) errors.number = 'validation.cardNumber';
  }
  if (draft.overview.type === 'identity') {
    const details = draft.details as IdentityDetails;
    if (details.email?.trim() && !isValidEmail(details.email.trim())) errors.email = 'validation.email';
  }
  if (draft.overview.type === 'environment') {
    const environment = draft.details as EnvironmentDetails;
    if (!draft.overview.title.trim()) errors.title = 'validation.titleRequired';
    environment.variables.forEach((variable, i) => {
      if (!variable.key.trim() && !variable.value) return;
      if (!validEnvironmentKey(variable.key.trim())) errors[`variables.${i}.key`] = 'env.invalidKey';
      else if (environment.variables.slice(0, i).some((one) => one.key.trim() === variable.key.trim())) errors[`variables.${i}.key`] = 'env.duplicateKey';
    });
    if (environment.project && !/^[A-Za-z0-9_-]{1,64}$/.test(environment.project.trim())) errors.project = 'env.invalidProject';
    if (environment.stage && !/^[A-Za-z0-9_-]{1,32}$/.test(environment.stage.trim())) errors.stage = 'env.invalidStage';
  }
  for (const [field, message] of validateItemFields(draft.overview.type, draft.details as unknown as Record<string, unknown>)) errors[field] = `validation.${message}` as MessageKey;
  if (draft.overview.type === 'sshKey' && !(draft.details as SshKeyDetails).privateKey) errors.privateKey = 'validation.sshKeyRequired';
  if (draft.overview.type === 'wifi') {
    const { ssid, security, password } = draft.details as WifiDetails;
    if (!ssid.trim()) errors.ssid = 'validation.ssidRequired';
    if (password && security === 'wep' && !isWepKey(password)) errors.password = 'validation.wepKey';
    if (password && hasPassword(security) && security !== 'wep' && !isEnterprise(security) && !isWpaPassword(password)) errors.password = 'validation.wpaPassword';
  }
  return errors;
}

/** WPA Personal: a passphrase of 8 to 63 characters, or the raw key as 64 hex digits. */
function isWpaPassword(password: string): boolean {
  return (password.length >= 8 && password.length <= 63) || /^[\da-f]{64}$/i.test(password);
}

function isWepKey(key: string): boolean {
  return key.length === 5 || key.length === 13 || /^([\da-f]{10}|[\da-f]{26})$/i.test(key);
}

// Leading or trailing spaces can be part of a secret, so these values are kept exactly as typed.
const VERBATIM = new Set(['password', 'value', 'cvv', 'pin', 'passphrase', 'answer', ...Object.values(ITEM_FIELDS).flatMap((fields) => fields.filter((field) => isSecretKind(field.kind)).map((field) => field.key))]);

/**
 * The fields this client edits: `1` is a value, an object lists known sub-fields, `[schema]` is a
 * list, and `'keep'` is shown but never edited here. Anything not listed (fields from a newer client)
 * is copied through untouched, as the item model requires.
 */
type Schema = 1 | 'keep' | Schema[] | { [key: string]: Schema };

const OVERVIEW: Schema = { title: 1, subtitle: 1, favorite: 1, pinned: 1, urls: [1], tags: [1] };
const LOGIN: Schema = {
  username: 1,
  password: 1,
  totp: 1,
  notes: 1,
  passkeys: 'keep',
  passwordHistory: 'keep',
  recovery: { email: 1, emailSource: 'keep', phone: 1, phoneSource: 'keep', twoFactorMethod: 1, backupCodes: [{ code: 1, used: 1 }], securityQuestions: [{ question: 1, answer: 1 }] },
  customFields: [{ label: 1, value: 1, hidden: 1 }],
  autoType: { sequence: 1, windowTitles: [1] },
};
const CUSTOM_FIELDS: Schema = [{ label: 1, value: 1, hidden: 1 }];

/** A type from the field table: its fields, then what every one of them has. */
function tableSchema(type: TableItemType, more: Record<string, Schema> = {}): Schema {
  return { ...Object.fromEntries(ITEM_FIELDS[type].map((field) => [field.key, 1 as Schema])), notes: 1, customFields: CUSTOM_FIELDS, ...more };
}

const DETAILS: Record<ItemType, Schema> = {
  bankAccount: tableSchema('bankAccount'),
  apiCredential: tableSchema('apiCredential'),
  softwareLicense: tableSchema('softwareLicense'),
  idDocument: tableSchema('idDocument'),
  cryptoWallet: tableSchema('cryptoWallet', { addresses: [{ network: 1, address: 1, label: 1 }] }),
  database: tableSchema('database', { passwordHistory: 'keep' }),
  // Field values are kept as typed; a field is dropped only when it has neither label nor value.
  custom: { templateId: 'keep', templateName: 'keep', notes: 1, fields: 'keep' },
  customTemplate: { fields: 'keep' },
  login: LOGIN,
  password: LOGIN,
  secureNote: { notes: 1 },
  // The network name is kept exactly: spaces at either end are part of it.
  wifi: {
    ssid: 'keep',
    security: 1,
    password: 1,
    hidden: 1,
    eapMethod: 1,
    phase2: 1,
    username: 1,
    identity: 1,
    serverDomain: 1,
    caCertificate: 1,
    captivePortal: 1,
    managed: 1,
    hotspot: 1,
    notes: 1,
    customFields: [{ label: 1, value: 1, hidden: 1 }],
    passwordHistory: 'keep',
  },
  // Made by the Tools section: here, only the notes and custom fields change.
  certificate: {
    certificate: 'keep',
    chain: 'keep',
    privateKey: 'keep',
    commonName: 'keep',
    sans: 'keep',
    issuer: 'keep',
    notBefore: 'keep',
    notAfter: 'keep',
    keyType: 'keep',
    fingerprint: 'keep',
    isCa: 'keep',
    source: 'keep',
    acme: 'keep',
    notes: 1,
    customFields: [{ label: 1, value: 1, hidden: 1 }],
  },
  key: {
    kind: 'keep',
    algorithm: 'keep',
    privateKey: 'keep',
    publicKey: 'keep',
    secret: 'keep',
    jwk: 'keep',
    jwks: 'keep',
    keyId: 'keep',
    fingerprint: 'keep',
    userId: 'keep',
    passphrase: 'keep',
    notes: 1,
    customFields: [{ label: 1, value: 1, hidden: 1 }],
  },
  // The key and what's read from it change only by generating or importing.
  sshKey: {
    privateKey: 'keep',
    publicKey: 'keep',
    keyType: 'keep',
    fingerprint: 'keep',
    comment: 1,
    passphrase: 1,
    sshAgent: 1,
    notes: 1,
    customFields: [{ label: 1, value: 1, hidden: 1 }],
  },
  card: { cardholder: 1, number: 1, expiry: 1, cvv: 1, pin: 1, brand: 1, notes: 1 },
  document: { notes: 1 },
  // Never edited here: Masked email connects and disconnects these.
  maskedEmailProvider: 'keep',
  // Never edited here: the Health page writes it.
  healthSettings: 'keep',
  // Nor these: Settings → Equivalent domains.
  equivalentDomains: 'keep',
  usageStats: 'keep',
  environment: {
    project: 1,
    projectName: 1,
    stage: 1,
    notes: 1,
    variables: [{ key: 1, value: 1, concealed: 1, note: 1 }],
  },
  identity: {
    firstName: 1,
    lastName: 1,
    email: 1,
    phone: 1,
    birthDate: 1,
    notes: 1,
    address: { line1: 1, line2: 1, city: 1, region: 1, postalCode: 1, country: 1 },
  },
};

function isEmpty(value: unknown): boolean {
  if (value === '' || value === undefined) return true;
  if (Array.isArray(value)) return value.length === 0;
  return typeof value === 'object' && value !== null && Object.keys(value).length === 0;
}

/** Trims and drops empty values in the fields this client edits. */
function prune(value: unknown, schema: Schema, key = ''): unknown {
  if (schema === 'keep') return value;
  if (schema === 1) return typeof value === 'string' && !VERBATIM.has(key) ? value.trim() : value;
  if (Array.isArray(schema)) {
    return Array.isArray(value) ? value.map((entry) => prune(entry, schema[0]!)).filter((entry) => !isEmpty(entry)) : value;
  }
  if (typeof value !== 'object' || value === null) return value;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value)) {
    if (!(k in schema)) {
      out[k] = v;
      continue;
    }
    const next = prune(v, schema[k]!, k);
    if (!isEmpty(next)) out[k] = next;
  }
  return out;
}

/** A sensible list subtitle, unless the user's existing subtitle is something custom. */
function subtitleFor(draft: ItemDraft, original: Item | undefined): string | undefined {
  const current = draft.overview.subtitle;
  switch (draft.overview.type) {
    case 'login': {
      const before = original && (original.details as LoginDetails).username;
      const username = (draft.details as LoginDetails).username;
      return !current || current === before ? username : current;
    }
    case 'card': {
      const { number, brand } = draft.details as CardDetails;
      const digits = number?.replace(/\D/g, '');
      if (current && !/ending \d{4}$/.test(current)) return current;
      return digits && digits.length >= 4 ? `${brand ?? detectCardBrand(digits) ?? 'Card'} ending ${digits.slice(-4)}` : current;
    }
    case 'identity': {
      const { firstName, lastName } = draft.details as IdentityDetails;
      return current || [firstName, lastName].filter(Boolean).join(' ') || undefined;
    }
    // Always the network name: the apps find the network the device is on by it.
    case 'wifi':
      return (draft.details as WifiDetails).ssid || undefined;
    case 'environment': {
      const environment = draft.details as EnvironmentDetails;
      return [environment.projectName || environment.project, environment.stage].filter(Boolean).join(' · ') || current;
    }
    // The fingerprint: it tells keys apart, and is what servers and other apps show.
    case 'sshKey':
      return (draft.details as SshKeyDetails).fingerprint || current;
    default: {
      const key = SUBTITLE_KEYS[draft.overview.type];
      return (key && (draft.details as unknown as Record<string, string | undefined>)[key]) || current;
    }
  }
}

export function cleanDraft(draft: ItemDraft, original?: Item): ItemDraft {
  const details = prune(draft.details, DETAILS[draft.overview.type]) as ItemDraft['details'];
  const overview = prune(draft.overview, OVERVIEW) as ItemDraft['overview'];
  if (draft.overview.type === 'secureNote') (details as { notes: string }).notes ??= '';
  if (isLoginLike(draft.overview.type)) {
    const login = details as LoginDetails;
    const fields = login.customFields?.filter((f) => f.label || f.value);
    if (fields?.length) login.customFields = fields;
    else delete login.customFields;
    if (login.recovery) {
      // A link means nothing without the value it came from.
      if (!login.recovery.email) delete login.recovery.emailSource;
      if (!login.recovery.phone) delete login.recovery.phoneSource;
      const codes = login.recovery.backupCodes?.filter((c) => c.code);
      if (codes?.length) login.recovery.backupCodes = codes;
      else delete login.recovery.backupCodes;
      const questions = login.recovery.securityQuestions?.filter((q) => q.question || q.answer);
      if (questions?.length) login.recovery.securityQuestions = questions;
      else delete login.recovery.securityQuestions;
      if (Object.keys(login.recovery).length === 0) delete login.recovery;
    }
  }
  if (draft.overview.type === 'card') {
    const card = details as CardDetails;
    if (card.number && !card.brand) {
      const brand = detectCardBrand(card.number);
      if (brand) card.brand = brand;
    }
  }
  if (draft.overview.type === 'wifi') {
    const wifi = details as WifiDetails;
    // Required, so kept even while empty.
    wifi.ssid ??= '';
    // Off switches and settings another security type doesn't use aren't kept.
    for (const flag of ['hidden', 'captivePortal', 'managed', 'hotspot'] as const) if (!wifi[flag]) delete wifi[flag];
    if (!hasPassword(wifi.security)) delete wifi.password;
    if (!isEnterprise(wifi.security)) for (const field of ['eapMethod', 'phase2', 'username', 'identity', 'serverDomain', 'caCertificate'] as const) delete wifi[field];
    if (wifi.eapMethod !== 'peap' && wifi.eapMethod !== 'ttls') delete wifi.phase2;
    const fields = wifi.customFields?.filter((f) => f.label || f.value);
    if (fields?.length) wifi.customFields = fields;
    else delete wifi.customFields;
    if (!overview.title) overview.title = wifi.ssid.trim();
  }
  if (draft.overview.type === 'environment') {
    const environment = details as EnvironmentDetails;
    environment.variables = (environment.variables ?? [])
      .filter((variable) => (variable.key ?? '').trim() || variable.value)
      .map((variable) => ({ ...variable, key: (variable.key ?? '').trim(), note: variable.note?.trim() || undefined }));
    if (environment.project) environment.project = environment.project.trim();
    else delete environment.project;
    if (environment.projectName) environment.projectName = environment.projectName.trim();
    else delete environment.projectName;
    if (environment.stage) environment.stage = environment.stage.trim();
    else delete environment.stage;
    if (environment.notes === '') delete environment.notes;
  }
  if (draft.overview.type === 'sshKey') {
    const key = details as SshKeyDetails;
    const fields = key.customFields?.filter((f) => f.label || f.value);
    if (fields?.length) key.customFields = fields;
    else delete key.customFields;
    if (!overview.title) overview.title = key.comment ?? '';
  }
  if (isTableType(draft.overview.type)) {
    const table = details as { customFields?: CustomField[] };
    const fields = table.customFields?.filter((f) => f.label || f.value);
    if (fields?.length) table.customFields = fields;
    else delete table.customFields;
  }
  if (draft.overview.type === 'cryptoWallet') {
    const wallet = details as CryptoWalletDetails;
    // A row with no address is one the person started and left.
    const addresses = wallet.addresses?.filter((entry) => entry.address);
    if (addresses?.length) wallet.addresses = addresses;
    else delete wallet.addresses;
  }
  if (draft.overview.type === 'custom') {
    const custom = details as CustomDetails;
    custom.fields = (custom.fields ?? []).map((field) => ({ ...field, label: field.label.trim() })).filter((field) => field.label || field.value);
  }
  if (draft.overview.type === 'customTemplate') {
    const template = details as CustomTemplateDetails;
    template.fields = (template.fields ?? []).map((field) => ({ ...field, label: field.label.trim() })).filter((field) => field.label);
  }
  // A site written twice ('https://a.example', 'a.example/login') is saved once, the first with its rule.
  if (overview.urls) {
    const typed = Object.fromEntries(Object.entries(draft.overview.urlMatch ?? {}).map(([url, mode]) => [url.trim(), mode]));
    overview.urls = uniqueWebsites(overview.urls, typed);
  }
  // Keyed by the URL as written, so only saved URLs keep a mode; the default isn't stored.
  const modes = Object.entries(draft.overview.urlMatch ?? {}).flatMap(([url, mode]) => (mode !== DEFAULT_URL_MATCH_MODE && overview.urls?.includes(url.trim()) ? [[url.trim(), mode] as const] : []));
  if (modes.length) overview.urlMatch = Object.fromEntries(modes);
  else delete overview.urlMatch;
  if (overview.tags) overview.tags = Array.from(new Set(overview.tags.map((t) => t.trim()).filter(Boolean)));
  if (overview.tags?.length === 0) delete overview.tags;
  const cleaned: ItemDraft = { ...draft, overview: { ...overview, schemaVersion: 1, type: draft.overview.type, title: overview.title ?? '' }, details: { ...details, schemaVersion: 1 } };
  const subtitle = subtitleFor(cleaned, original);
  if (subtitle) cleaned.overview.subtitle = subtitle;
  else delete cleaned.overview.subtitle;
  return cleaned;
}

export function parseTags(text: string): string[] {
  return text.split(',').map((tag) => tag.trim()).filter(Boolean);
}
