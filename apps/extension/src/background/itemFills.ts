// Autofill from the newer item types (plan 05, History 2026-11-08): bank accounts, databases,
// software licences, ID documents and crypto wallets.
//
// None of them is tied to a website the way a login is, so they're offered like cards: only in the
// fields that take them, which the engine recognises on the page, and only filled after the user picks
// one. A database is offered in a database console's sign-in (a server or database field beside one
// password), the ones saved for the page or on its host first. Lists never carry a secret: a bank
// account shows the last four characters of its IBAN or account number, as a card does. A wallet
// fills one receiving address; its seed phrase and passphrase are never filled anywhere.

import type { FillValues, Suggestion } from '@octapass/autofill';
import type {
  BankAccountDetails,
  CryptoWalletDetails,
  DatabaseDetails,
  IdDocumentDetails,
  Item,
  ItemSummary,
  SoftwareLicenseDetails,
} from '@octapass/vault-client';
import { webPage, type Matcher } from './matching';
import type { VaultHost } from './vault';

/** A wallet address entry's id: the item, then the address's place in it. */
const WALLET_SEPARATOR = '#';

export function walletSuggestionId(itemId: string, index: number): string {
  return `${itemId}${WALLET_SEPARATOR}${index}`;
}

/** The item a suggestion fills from: a wallet entry names an address within it. */
export function suggestionItemId(suggestion: Pick<Suggestion, 'kind' | 'id'>): { itemId: string; index?: number } {
  if (suggestion.kind !== 'crypto-wallet') return { itemId: suggestion.id };
  const at = suggestion.id.lastIndexOf(WALLET_SEPARATOR);
  const index = Number(suggestion.id.slice(at + 1));
  return at > 0 && Number.isInteger(index) && index >= 0 ? { itemId: suggestion.id.slice(0, at), index } : { itemId: suggestion.id };
}

const lastFour = (text: string | undefined) => {
  const compact = text?.replace(/[\s-]/g, '');
  return compact && compact.length > 4 ? `•••• ${compact.slice(-4)}` : undefined;
};

const shortAddress = (address: string) => (address.length > 16 ? `${address.slice(0, 8)}…${address.slice(-6)}` : address);

async function details<T>(host: VaultHost, summary: ItemSummary): Promise<T | undefined> {
  const item = await host.getItem(summary.id).catch(() => undefined);
  return item && !item.deletedAt && item.overview.type === summary.type ? (item.details as T) : undefined;
}

const live = (items: ItemSummary[], type: ItemSummary['type']) => items.filter((i) => i.type === type && !i.deletedAt);

export async function bankSuggestions(host: VaultHost, items: ItemSummary[]): Promise<Suggestion[]> {
  const found = await Promise.all(
    live(items, 'bankAccount').map(async (summary): Promise<Suggestion | undefined> => {
      const bank = await details<BankAccountDetails>(host, summary);
      if (!bank || !(bank.iban || bank.accountNumber || bank.routingNumber || bank.swift)) return undefined;
      const subtitle = lastFour(bank.iban || bank.accountNumber) ?? summary.subtitle;
      return { kind: 'bank-account', id: summary.id, title: summary.title, ...(subtitle ? { subtitle } : {}) };
    }),
  );
  return found.filter((s) => s !== undefined);
}

/** Licences and ID documents fill one value; those without it aren't listed. */
export async function singleValueSuggestions(
  host: VaultHost,
  items: ItemSummary[],
  kind: 'software-license' | 'id-document',
): Promise<Suggestion[]> {
  const type = kind === 'software-license' ? 'softwareLicense' : 'idDocument';
  const found = await Promise.all(
    live(items, type).map(async (summary): Promise<Suggestion | undefined> => {
      const value = kind === 'software-license' ? (await details<SoftwareLicenseDetails>(host, summary))?.licenseKey : (await details<IdDocumentDetails>(host, summary))?.number;
      return value ? { kind, id: summary.id, title: summary.title, ...(summary.subtitle ? { subtitle: summary.subtitle } : {}) } : undefined;
    }),
  );
  return found.filter((s) => s !== undefined);
}

/** One entry per receiving address. An address isn't a secret: the item shows it as a QR code. */
export async function walletSuggestions(host: VaultHost, items: ItemSummary[]): Promise<Suggestion[]> {
  const found = await Promise.all(
    live(items, 'cryptoWallet').map(async (summary) => {
      const wallet = await details<CryptoWalletDetails>(host, summary);
      return (wallet?.addresses ?? []).flatMap((entry, index): Suggestion[] =>
        entry.address
          ? [{ kind: 'crypto-wallet', id: walletSuggestionId(summary.id, index), title: summary.title, subtitle: [entry.label || entry.network, shortAddress(entry.address)].filter(Boolean).join(' · ') }]
          : [],
      );
    }),
  );
  return found.flat();
}

/** Databases with something to sign in with, those saved for the page or on its host first. */
export async function databaseSuggestions(host: VaultHost, matcher: Pick<Matcher, 'belongs'>, items: ItemSummary[], pageUrl: string): Promise<Suggestion[]> {
  const pageHost = webPage(pageUrl)?.hostname.toLowerCase();
  const found = await Promise.all(
    live(items, 'database').map(async (summary) => {
      const database = await details<DatabaseDetails>(host, summary);
      if (!database || !(database.username || database.password)) return undefined;
      const here = matcher.belongs(summary, pageUrl) || (!!pageHost && database.host?.trim().toLowerCase() === pageHost);
      const suggestion: Suggestion = { kind: 'database', id: summary.id, title: summary.title, ...(summary.subtitle ? { subtitle: summary.subtitle } : {}) };
      return { suggestion, here };
    }),
  );
  const listed = found.filter((f) => f !== undefined);
  return [...listed.filter((f) => f.here), ...listed.filter((f) => !f.here)].map((f) => f.suggestion);
}

/** What a picked entry of one of these kinds fills, or null when the item isn't of that kind. */
export function itemFillValues(suggestion: Pick<Suggestion, 'kind' | 'id'>, item: Item): FillValues | null {
  const type = item.overview.type;
  const pick = (entries: [keyof FillValues, string | undefined][]) => {
    const values = Object.fromEntries(entries.filter(([, value]) => value)) as FillValues;
    return Object.keys(values).length > 0 ? values : null;
  };
  switch (suggestion.kind) {
    case 'bank-account': {
      if (type !== 'bankAccount') return null;
      const bank = item.details as BankAccountDetails;
      return pick([
        ['bank-account-holder', bank.accountHolder],
        ['iban', bank.iban],
        ['bic', bank.swift],
        ['bank-name', bank.bankName],
        ['bank-account-number', bank.accountNumber],
        ['bank-routing', bank.routingNumber],
      ]);
    }
    case 'database': {
      if (type !== 'database') return null;
      const database = item.details as DatabaseDetails;
      return pick([
        ['db-host', database.host],
        ['db-port', database.port],
        ['db-name', database.database],
        ['username', database.username],
        ['current-password', database.password],
      ]);
    }
    case 'software-license':
      return type === 'softwareLicense' ? pick([['license-key', (item.details as SoftwareLicenseDetails).licenseKey]]) : null;
    case 'id-document':
      return type === 'idDocument' ? pick([['document-number', (item.details as IdDocumentDetails).number]]) : null;
    case 'crypto-wallet': {
      const { index } = suggestionItemId(suggestion);
      if (type !== 'cryptoWallet' || index === undefined) return null;
      // Only an address, never the seed phrase or passphrase.
      return pick([['wallet-address', (item.details as CryptoWalletDetails).addresses?.[index]?.address]]);
    }
    default:
      return null;
  }
}
