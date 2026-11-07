// The recovery map (plan 01, Recovery info): which emails and phones can reset which logins, and
// whether each email's own account is protected. Runs on the device over decrypted items.

import { isValidEmail, normalizeEmail } from '../items';
import type { HealthEntry, HealthReport, Item, LoginDetails, RecoveryContact } from '../types';
import { hostnameOf, registrableDomain } from './url';

// Mail domains whose account lives on another site: a Gmail address signs in at google.com.
const GOOGLE = ['google.com'];
const MICROSOFT = ['live.com', 'microsoft.com', 'outlook.com'];
const YAHOO = ['yahoo.com'];
const APPLE = ['apple.com', 'icloud.com'];
const PROTON = ['proton.me', 'protonmail.com'];
const GMX = ['gmx.com', 'gmx.net', 'gmx.de'];
const YANDEX = ['yandex.com', 'yandex.ru'];
const TUTA = ['tuta.com', 'tutanota.com'];
const MAIL_SITES: Record<string, string[]> = {
  'gmail.com': GOOGLE,
  'googlemail.com': GOOGLE,
  'outlook.com': MICROSOFT,
  'hotmail.com': MICROSOFT,
  'live.com': MICROSOFT,
  'msn.com': MICROSOFT,
  'yahoo.com': YAHOO,
  'ymail.com': YAHOO,
  'icloud.com': APPLE,
  'me.com': APPLE,
  'mac.com': APPLE,
  'proton.me': PROTON,
  'protonmail.com': PROTON,
  'pm.me': PROTON,
  'gmx.com': GMX,
  'gmx.net': GMX,
  'gmx.de': GMX,
  'yandex.com': YANDEX,
  'yandex.ru': YANDEX,
  'tuta.io': TUTA,
  'tutanota.com': TUTA,
};

/** The sites where an email address's own account signs in. */
export function mailSitesFor(email: string): string[] {
  const domain = registrableDomain(email.slice(email.lastIndexOf('@') + 1));
  return MAIL_SITES[domain] ?? [domain];
}

/** A phone number reduced to its digits (and a leading +), so spacing doesn't split a group. */
export function normalizePhone(phone: string): string {
  const trimmed = phone.trim();
  return (trimmed.startsWith('+') ? '+' : '') + trimmed.replace(/\D/g, '');
}

export function entryOf(item: Item): HealthEntry {
  const subtitle = item.overview.subtitle ?? (item.details as LoginDetails).username;
  return {
    itemId: item.id,
    vaultId: item.vaultId,
    title: item.overview.title,
    ...(subtitle !== undefined && { subtitle }),
  };
}

export function hasTwoStep(details: LoginDetails): boolean {
  const method = details.recovery?.twoFactorMethod;
  return Boolean(details.totp) || (details.passkeys?.length ?? 0) > 0 || (method !== undefined && method !== 'none');
}

interface Group {
  contact: RecoveryContact;
  ids: Set<string>;
}

/** Logins grouped by recovery email and phone, plus the emails whose own login lacks two-step sign-in. */
export function buildRecoveryMap(items: Item[]): Pick<HealthReport, 'recovery' | 'recoveryNo2fa'> {
  const logins = items.filter((item) => item.overview.type === 'login');
  const groups = new Map<string, Group>();

  const add = (kind: RecoveryContact['kind'], value: string, item: Item, details: LoginDetails) => {
    const key = `${kind}:${kind === 'email' ? normalizeEmail(value) : normalizePhone(value)}`;
    let group = groups.get(key);
    if (!group) {
      group = { contact: { kind, value: value.trim(), logins: [] }, ids: new Set() };
      groups.set(key, group);
    }
    if (!group.ids.has(item.id)) {
      group.ids.add(item.id);
      group.contact.logins.push(entryOf(item));
    }
    const source = kind === 'email' ? details.recovery?.emailSource : details.recovery?.phoneSource;
    if (source?.kind === 'alias' && !group.contact.aliasProvider) {
      group.contact.aliasProvider = source.provider;
      group.contact.aliasId = source.aliasId;
    }
    if (source?.kind === 'identity') group.contact.identityId ??= source.itemId;
  };

  for (const item of logins) {
    const details = item.details as LoginDetails;
    const email = details.recovery?.email?.trim();
    const phone = details.recovery?.phone?.trim();
    const username = details.username?.trim();
    if (email) add('email', email, item, details);
    // Sites send password resets to the email you sign in with, so it counts as a recovery email too.
    if (username && isValidEmail(username) && normalizeEmail(username) !== normalizeEmail(email ?? '')) add('email', username, item, details);
    if (phone && normalizePhone(phone).replace('+', '').length > 0) add('phone', phone, item, details);
  }

  const recovery: RecoveryContact[] = [];
  const recoveryNo2fa: HealthReport['recoveryNo2fa'] = [];
  for (const { contact } of groups.values()) {
    if (contact.kind === 'email') {
      const account = accountFor(contact.value, logins);
      if (account) {
        contact.logins = contact.logins.filter((entry) => entry.itemId !== account.id);
        const twoStep = hasTwoStep(account.details as LoginDetails);
        contact.account = { ...entryOf(account), twoStep };
        if (!twoStep && contact.logins.length > 0) recoveryNo2fa.push({ ...entryOf(account), email: contact.value, accounts: contact.logins.length });
      }
    }
    if (contact.logins.length > 0) recovery.push(contact);
  }
  recovery.sort((a, b) => b.logins.length - a.logins.length || a.value.localeCompare(b.value));
  recoveryNo2fa.sort((a, b) => b.accounts - a.accounts || a.email.localeCompare(b.email));
  return { recovery, recoveryNo2fa };
}

/** The email account's own login: signed in with that address (or its local part) on its mail site. */
function accountFor(email: string, logins: Item[]): Item | undefined {
  const address = normalizeEmail(email);
  const local = address.slice(0, address.lastIndexOf('@'));
  const sites = new Set(mailSitesFor(address));
  return logins.find((item) => {
    const username = normalizeEmail((item.details as LoginDetails).username ?? '');
    if (username !== address && username !== local) return false;
    return (item.overview.urls ?? []).some((url) => {
      const host = hostnameOf(url);
      return host !== undefined && sites.has(registrableDomain(host));
    });
  });
}
