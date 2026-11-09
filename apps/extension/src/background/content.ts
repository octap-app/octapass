// Answers content scripts. They only learn about logins and one-time codes for the page they run
// in, as the browser reports it, and only get a secret back for an item that matches that page.
// Cards and identities aren't tied to a site; they're offered in card and address fields only.
// API credentials are tied to a site exactly as logins are. Bank accounts, databases, licences, ID
// documents and wallet addresses are offered like cards, in their own fields only (`itemFills.ts`).
// A frame from another site than the page gets nothing until the user allows it (`frames.ts`).
// Logins for other parts of the page's site are listed apart, filled only when the user picks one
// from that list, and only after checking here that they really are for another part of this site.

import { BANK_FIELD_TYPES, DATABASE_FIELD_TYPES, type FieldType, type FillValues, type Suggestion } from '@octapass/autofill';
import type { PasswordRules, RandomGeneratorOptions } from '@octapass/core/full';
import {
  DEFAULT_PASSWORD_OPTIONS,
  isHotp,
  isVaultError,
  loginDetails,
  type ApiCredentialDetails,
  type CardDetails,
  type IdentityDetails,
  type Item,
  type ItemType,
} from '@octapass/vault-client';
import type { AutoFillResponse, ContentRequest, FieldContext, ResolveResponse, SaveResponse, SavePrompt, SuggestionsResponse, WebsitePrompt } from '../shared/messages';
import type { WebsiteAdder } from './addWebsite';
import { apiCredentialFillValues, credentialValue, type ApiKeySaver } from './apiKeys';
import type { AutofillAuth } from './deviceAuth';
import type { DetailsSaver } from './detailsSaves';
import { fillOnLoadEnabled, loginToFill } from './fillOnLoad';
import { bankSuggestions, databaseSuggestions, itemFillValues, singleValueSuggestions, suggestionItemId, walletSuggestions } from './itemFills';
import type { FrameApprovals } from './frames';
import type { MaskedEmailFiller } from './maskedEmail';
import { webPage, type Matcher } from './matching';
import type { LoginSaver } from './saves';
import type { SiteIcons } from './siteIcons';
import type { PageSender } from './senders';
import type { VaultHost } from './vault';

/** The menu entry shown while the vault is locked; picking it opens the popup. */
export const UNLOCK_SUGGESTION = 'octapass:unlock';
export const MASKED_EMAIL_SUGGESTION = 'octapass:masked-email';
export const OTHER_LOGINS_SUGGESTION = 'octapass:other-logins';

const LOGIN_FIELDS = new Set<FieldType>(['username', 'current-password']);
const NEW_PASSWORD_FIELDS = new Set<FieldType>(['new-password', 'confirm-password']);
const BANK_FIELDS = new Set<FieldType>(BANK_FIELD_TYPES);
const DATABASE_FIELDS = new Set<FieldType>(DATABASE_FIELD_TYPES);
const IDENTITY_FIELDS = new Set<FieldType>([
  'email', 'name', 'given-name', 'family-name', 'tel', 'organization', 'bday',
  'address-line1', 'address-line2', 'address-level2', 'address-level1', 'postal-code', 'country',
]);

/** A login's username and password, only when it's saved for `pageUrl`. */
export function loginFillValues(matcher: Matcher, item: Item, pageUrl: string): FillValues | null {
  const login = item.deletedAt ? undefined : loginDetails(item);
  if (!login || !matcher.belongs(item.overview, pageUrl)) return null;
  return { ...(login.username ? { username: login.username } : {}), ...(login.password ? { 'current-password': login.password } : {}) };
}

/**
 * A login's username and password, only when it's saved for another part of `pageUrl`'s site: what
 * the user picked from "Logins for other parts of …". Never for the page's own logins or other sites.
 */
export function otherLoginFillValues(matcher: Matcher, item: Item, pageUrl: string): FillValues | null {
  const login = item.deletedAt ? undefined : loginDetails(item);
  if (!login || !matcher.otherPart(item.overview, pageUrl)) return null;
  return { ...(login.username ? { username: login.username } : {}), ...(login.password ? { 'current-password': login.password } : {}) };
}

function cardValues(details: CardDetails, cvv: boolean): FillValues {
  const values: FillValues = {};
  if (details.cardholder) values['cc-name'] = details.cardholder;
  if (details.number) values['cc-number'] = details.number.replace(/\s/g, '');
  if (details.expiry) values['cc-exp'] = details.expiry;
  if (details.cvv && cvv) values['cc-csc'] = details.cvv;
  return values;
}

function identityValues(details: IdentityDetails): FillValues {
  const name = [details.firstName, details.lastName].filter(Boolean).join(' ');
  const entries: [keyof FillValues, string | undefined][] = [
    ['name', name || undefined],
    ['given-name', details.firstName],
    ['family-name', details.lastName],
    ['email', details.email],
    ['tel', details.phone],
    ['bday', details.birthDate],
    ['address-line1', details.address?.line1],
    ['address-line2', details.address?.line2],
    ['address-level2', details.address?.city],
    ['address-level1', details.address?.region],
    ['postal-code', details.address?.postalCode],
    ['country', details.address?.country],
  ];
  return Object.fromEntries(entries.filter(([, v]) => v)) as FillValues;
}

export interface PasswordRulesCore {
  passwordRulesTextForSite(url: string): string | undefined;
  parsePasswordRules(text: string): PasswordRules;
  generateForRules(rules: PasswordRules, options: RandomGeneratorOptions | undefined): string;
}

/**
 * A strong password the site accepts: its known rules (the core's per-site dataset), the field's
 * `passwordrules`, `minlength` and `maxlength`, and its `pattern`, which rules can't express, by retrying.
 */
export function suggestPassword(core: PasswordRulesCore, url: string, constraints: FieldContext['passwordConstraints']): string {
  const text = [
    core.passwordRulesTextForSite(url),
    constraints?.rules,
    constraints?.minLength ? `minlength: ${constraints.minLength}` : undefined,
    constraints?.maxLength ? `maxlength: ${constraints.maxLength}` : undefined,
  ]
    .filter(Boolean)
    .join('; ');
  const rules = core.parsePasswordRules(text);
  const { kind: _kind, ...options } = DEFAULT_PASSWORD_OPTIONS;
  let pattern: RegExp | undefined;
  try {
    pattern = constraints?.pattern ? new RegExp(`^(?:${constraints.pattern})$`, 'v') : undefined;
  } catch {
    pattern = undefined;
  }
  for (const symbols of [true, false]) {
    for (let attempt = 0; attempt < 20; attempt++) {
      const password = core.generateForRules(rules, { ...options, symbols });
      if (!pattern || pattern.test(password)) return password;
    }
  }
  return core.generateForRules(rules, options);
}

export interface ContentContext {
  host: VaultHost;
  saver: LoginSaver;
  details: DetailsSaver;
  apiKeys: ApiKeySaver;
  matcher: Matcher;
  frames: FrameApprovals;
  rules: PasswordRulesCore;
  masked: MaskedEmailFiller;
  icons: SiteIcons;
  /** Offers to add the page's website to a login filled from another part of the site. */
  websites: WebsiteAdder;
  /** "Ask on every fill": device auth before a login, code, card or identity goes to the page. */
  fillAuth?: AutofillAuth;
  /** "Fill logins when a page opens". Test seam: `chrome.storage.local` otherwise. */
  fillOnLoad?: () => Promise<boolean>;
  /** Opens the app tab for the page's tab, to unlock and come back. */
  openApp: (tabId: number) => Promise<void>;
  /** The user did something with the vault. */
  touch: () => void;
}

async function suggestions({ host, matcher, frames, rules, masked }: ContentContext, field: FieldContext, sender: PageSender): Promise<SuggestionsResponse> {
  const status = host.snapshot.session.status;
  const { fieldType } = field;
  const access = await frames.check(sender);
  if (!access.allowed) return { status, suggestions: access.ask ? [{ kind: 'frame-approval', id: crypto.randomUUID(), ...access.ask }] : [] };
  if (status !== 'unlocked') {
    const unlock = status === 'locked' && (LOGIN_FIELDS.has(fieldType) || fieldType === 'one-time-code' || fieldType === 'api-credential');
    // The engine shows a field only the kinds it takes. The content script puts the title in the user's language.
    return { status, suggestions: unlock ? [{ kind: fieldType === 'api-credential' ? 'api-credential' : 'login', id: UNLOCK_SUGGESTION, title: 'Unlock Octa Pass' }] : [] };
  }
  if (NEW_PASSWORD_FIELDS.has(fieldType)) {
    return { status, suggestions: [{ kind: 'generated-password', id: crypto.randomUUID(), password: suggestPassword(rules, sender.url, field.passwordConstraints) }] };
  }
  const items = await host.listItems();
  const byType = (type: ItemType) => items.filter((i) => i.type === type);
  let list: Suggestion[] = [];
  if (LOGIN_FIELDS.has(fieldType)) {
    list = matcher.logins(items, sender.url).map((l) => ({ kind: 'login', id: l.id, title: l.title, ...(l.subtitle ? { username: l.subtitle } : {}) }));
    // Last, as one quiet entry: never filled unless the user opens it and picks one.
    const others = matcher.otherLogins(items, sender.url);
    if (others.length) {
      list.push({
        kind: 'other-logins',
        id: OTHER_LOGINS_SUGGESTION,
        site: others[0]!.site,
        logins: others.map(({ item, host }) => ({ id: item.id, title: item.title, host, ...(item.subtitle ? { username: item.subtitle } : {}) })),
      });
    }
    // A database console's sign-in: then the databases.
    if (field.formType === 'database') list.push(...(await databaseSuggestions(host, matcher, items, sender.url)));
  } else if (DATABASE_FIELDS.has(fieldType)) {
    list = await databaseSuggestions(host, matcher, items, sender.url);
  } else if (BANK_FIELDS.has(fieldType)) {
    list = await bankSuggestions(host, items);
  } else if (fieldType === 'license-key') {
    list = await singleValueSuggestions(host, items, 'software-license');
  } else if (fieldType === 'document-number') {
    list = await singleValueSuggestions(host, items, 'id-document');
  } else if (fieldType === 'wallet-address') {
    list = await walletSuggestions(host, items);
  } else if (fieldType === 'one-time-code') {
    list = matcher
      .logins(items, sender.url)
      .filter((l) => l.hasTotp)
      .map((l) => ({ kind: 'one-time-code', id: l.id, title: l.subtitle ? `${l.title} (${l.subtitle})` : l.title }));
  } else if (fieldType === 'api-credential') {
    // Only items with a value to give: an OAuth client whose token ran out has nothing to fill.
    const now = Math.floor(Date.now() / 1000);
    const matched = await Promise.all(
      matcher.apiCredentials(items, sender.url).map(async (c) => {
        const item = await host.getItem(c.id).catch(() => undefined);
        return item && credentialValue(item.details as ApiCredentialDetails, now) ? c : undefined;
      }),
    );
    list = matched.filter((c) => c !== undefined).map((c) => ({ kind: 'api-credential', id: c.id, title: c.title, ...(c.subtitle ? { subtitle: c.subtitle } : {}) }));
  } else if (fieldType.startsWith('cc-')) {
    list = await Promise.all(
      byType('card').map(async (c) => {
        const last4 = ((await host.getItem(c.id)).details as CardDetails).number?.replace(/\s/g, '').slice(-4);
        return { kind: 'card' as const, id: c.id, title: c.title, ...(last4 ? { subtitle: `•••• ${last4}` } : {}) };
      }),
    );
  } else if (IDENTITY_FIELDS.has(fieldType)) {
    list = byType('identity').map((i) => ({ kind: 'identity', id: i.id, title: i.title, ...(i.subtitle ? { subtitle: i.subtitle } : {}) }));
    // Without a provider the engine shows the entry as "Needs setup".
    if (fieldType === 'email' && field.formType === 'signup' && (await masked.available().catch(() => false))) {
      list.unshift({ kind: 'masked-email', id: MASKED_EMAIL_SUGGESTION });
    }
  }
  return { status, suggestions: list };
}

async function resolve(context: ContentContext, suggestion: Pick<Suggestion, 'kind' | 'id'>, sender: PageSender): Promise<ResolveResponse> {
  const { host } = context;
  if (suggestion.id === UNLOCK_SUGGESTION) {
    await context.openApp(sender.tabId);
    return null;
  }
  if (!host.unlocked) return null;
  if (suggestion.kind === 'masked-email') {
    try {
      const alias = await context.masked.create(sender);
      context.touch();
      return { email: alias.email };
    } catch (error) {
      return { error: isVaultError(error) ? error.code : 'unexpected' };
    }
  }
  const item = await host.getItem(suggestionItemId(suggestion).itemId).catch(() => undefined);
  if (!item || item.deletedAt) return null;
  // The autofill gate: only when actually filling, never for opening the vault or listing suggestions.
  const card = suggestion.kind === 'card' && item.overview.type === 'card' ? (item.details as CardDetails) : undefined;
  const cardAnswer = card ? await (context.fillAuth?.requestCard(Boolean(card.cvv)) ?? { fill: true, cvv: true }) : undefined;
  if (cardAnswer ? !cardAnswer.fill : context.fillAuth && !(await context.fillAuth.request())) return null;
  let values: FillValues | null = null;
  switch (suggestion.kind) {
    case 'login':
      values = loginFillValues(context.matcher, item, sender.url);
      break;
    case 'other-login':
      values = otherLoginFillValues(context.matcher, item, sender.url);
      break;
    case 'one-time-code': {
      const totp = loginFillValues(context.matcher, item, sender.url) && loginDetails(item)?.totp;
      // A counter-based code is used up by filling it: the fill moves and saves the counter first.
      if (totp) values = { 'one-time-code': (await (isHotp(totp) ? host.engine.call('nextHotpCode', [item.id]) : host.engine.call('totpCode', [totp, undefined]))).code };
      break;
    }
    case 'api-credential':
      values = apiCredentialFillValues(context.matcher, item, sender.url);
      break;
    case 'card':
      if (card) values = cardValues(card, cardAnswer!.cvv);
      break;
    case 'identity':
      if (item.overview.type === 'identity') values = identityValues(item.details as IdentityDetails);
      break;
    case 'bank-account':
    case 'database':
    case 'software-license':
    case 'id-document':
    case 'crypto-wallet':
      values = itemFillValues(suggestion, item);
      break;
  }
  if (values) {
    context.touch();
    host.usage.record(item.id);
    // Asked for once the page says the fill went through (`websitePrompt`).
    if (suggestion.kind === 'other-login') await context.websites.offer(item, sender.url, sender.tabId).catch(() => null);
  }
  return values;
}

/**
 * A fill on page load, with no pick: only with the setting on, while unlocked, in the top frame of an
 * https page, when filling wouldn't ask first, and only a login saved for the page's own host (the
 * one used last, or the only one). It doesn't count as a use: only the user's own fills do.
 */
async function autoFill(context: ContentContext, sender: PageSender): Promise<AutoFillResponse> {
  const { host, matcher } = context;
  if (sender.frameId !== 0 || !host.unlocked || !(await (context.fillOnLoad ?? fillOnLoadEnabled)())) return null;
  if (webPage(sender.url)?.protocol !== 'https:') return null;
  if (context.fillAuth && (await context.fillAuth.wouldAsk())) return null;
  const logins = matcher.ownHostLogins(await host.listItems(), sender.url);
  if (logins.length === 0) return null;
  const chosen = loginToFill(logins, await host.usage.read().catch(() => ({})));
  const item = chosen && (await host.getItem(chosen.id).catch(() => undefined));
  const values = item ? loginFillValues(matcher, item, sender.url) : null;
  if (!values?.username && !values?.['current-password']) return null;
  return { ...(values.username ? { username: values.username } : {}), ...(values['current-password'] ? { 'current-password': values['current-password'] } : {}) };
}

/** Only for a login saved for the page asking, so a page learns nothing it couldn't fill. */
async function siteIcon({ host, matcher, icons }: ContentContext, id: string, sender: PageSender): Promise<string | null> {
  if (!host.unlocked) return null;
  const item = (await host.listItems()).find((i) => i.id === id && i.type === 'login');
  if (!item || !matcher.belongs(item, sender.url)) return null;
  return icons.forUrls(item.urls).catch(() => null);
}

export async function handleContent(
  context: ContentContext,
  message: ContentRequest,
  sender: PageSender,
): Promise<SuggestionsResponse | ResolveResponse | AutoFillResponse | SaveResponse | SavePrompt | WebsitePrompt | string | boolean | void | null> {
  if (message.type === 'suggestions') return suggestions(context, message.field, sender);
  if (message.type === 'approveFrame') return context.frames.approve(sender);
  // Nothing else for a frame the user hasn't allowed: no fills, no saves.
  if (!(await context.frames.check(sender)).allowed) return null;
  switch (message.type) {
    case 'resolve':
      return resolve(context, message.suggestion, sender);
    case 'autoFill':
      return autoFill(context, sender);
    case 'save':
      return context.saver.report(message.report, sender);
    case 'saveDetails':
      return context.details.report(message.report, sender);
    case 'offerApiKey':
      return context.apiKeys.offer(message.apiKey, sender);
    case 'pendingSave':
      return context.saver.waiting(sender) ?? context.details.waiting(sender);
    case 'answerSave':
      context.touch();
      // Each saver ignores an id that isn't its own.
      await context.saver.answer(message.id, message.answer, sender);
      await context.details.answer(message.id, message.answer, message.saveCode === true, sender);
      return context.apiKeys.answer(message.id, message.answer, message.credential, sender);
    case 'openApp':
      return context.openApp(sender.tabId);
    case 'siteIcon':
      return siteIcon(context, message.id, sender);
    case 'websitePrompt':
      return context.websites.waiting(sender.tabId, message.id, sender.url);
    case 'answerWebsite':
      context.touch();
      return context.websites.answer(message.id, message.answer, sender.tabId);
    case 'language':
      // Answered by the service worker's listener before it gets here.
      return;
  }
}
