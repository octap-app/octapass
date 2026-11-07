// Payment QR codes (plan 01): EPC QR for bank accounts and `bitcoin:` / `ethereum:` address URIs for
// wallets. Only receiving details ever go in: never a PIN, a seed phrase or a passphrase. The core has
// the same functions in `crates/octapass-core/src/tools/payment_qr.rs`; `tests/vectors/payment-qr.json`
// there checks both.

import { isIban, isSwift, normalizeIban } from './itemFields';
import type { WalletAddress } from './types';

/** What an EPC QR code asks a banking app to pay. */
export interface EpcPayment {
  name: string;
  iban: string;
  bic?: string;
  /** In euros, like `12.50`. */
  amount?: string;
  /** Free text for the payee, at most 140 characters. */
  reference?: string;
}

/** Countries in the SEPA schemes. An EPC QR code means nothing to a bank outside them. */
const SEPA_COUNTRIES = new Set('AD AL AT BE BG CH CY CZ DE DK EE ES FI FR GB GI GR HR HU IE IS IT LI LT LU LV MC MD ME MK MT NL NO PL PT RO RS SE SI SK SM'.split(' '));

/** Whether this IBAN can be paid with an EPC QR code: valid, and in a SEPA country. */
export function isSepaIban(iban: string): boolean {
  const clean = normalizeIban(iban);
  return isIban(clean) && SEPA_COUNTRIES.has(clean.slice(0, 2));
}

function epcAmount(amount: string): string | undefined {
  const match = /^(\d{1,9})(?:\.(\d{0,2}))?$/.exec(amount);
  if (!match) return undefined;
  const whole = match[1]!.replace(/^0+/, '');
  const decimals = (match[2] ?? '').replace(/0+$/, '');
  if (!whole && !decimals) return undefined;
  return `EUR${whole || '0'}.${decimals.padEnd(2, '0')}`;
}

/** A line break or a control character would start another EPC line, so they become spaces. */
function epcText(text: string, limit: number): string | undefined {
  // eslint-disable-next-line no-control-regex
  const clean = text.trim().replace(/[\u0000-\u001f\u007f-\u009f]/g, ' ');
  return [...clean].length <= limit ? clean : undefined;
}

/**
 * The EPC QR text (EPC069-12 version 002, UTF-8, SEPA credit transfer), or undefined when the IBAN
 * isn't a SEPA one, there's no payee name, or a value doesn't fit the format.
 */
export function epcQrText(payment: EpcPayment): string | undefined {
  if (!isSepaIban(payment.iban)) return undefined;
  const name = epcText(payment.name, 70);
  if (!name) return undefined;
  const bic = (payment.bic ?? '').trim();
  if (bic && !isSwift(bic)) return undefined;
  const rawAmount = (payment.amount ?? '').trim();
  const amount = rawAmount ? epcAmount(rawAmount) : '';
  if (amount === undefined) return undefined;
  const reference = epcText(payment.reference ?? '', 140);
  if (reference === undefined) return undefined;
  const lines = ['BCD', '002', '1', 'SCT', bic.toUpperCase(), name, normalizeIban(payment.iban), amount, '', '', reference];
  // Empty lines at the end are left out.
  while (!lines[lines.length - 1]) lines.pop();
  return lines.join('\n');
}

/** One word of letters and digits: what any chain's address looks like, and what a seed phrase, which is several words, doesn't. */
export function looksLikeAddress(address: string): boolean {
  return /^[A-Za-z\d:_-]{16,128}$/.test(address);
}

function isBitcoinAddress(address: string): boolean {
  const bech32 = /^(bc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{11,71}|BC1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{11,71})$/;
  const base58 = /^[13][1-9A-HJ-NP-Za-km-z]{25,34}$/;
  return bech32.test(address) || base58.test(address);
}

/** The URI a wallet app opens to pay an address (BIP 21, EIP-681), or undefined for another network or a value that isn't an address. */
export function addressUri(network: string, address: string): string | undefined {
  const value = address.trim();
  const chain = network.trim().toLowerCase();
  if ((chain === 'bitcoin' || chain === 'btc') && isBitcoinAddress(value)) return `bitcoin:${value}`;
  if ((chain === 'ethereum' || chain === 'eth') && /^0x[\da-fA-F]{40}$/.test(value)) return `ethereum:${value}`;
  return undefined;
}

/** What a wallet address shows as a QR code: its URI where there's a standard, else the address. Never anything else. */
export function addressQrText(entry: WalletAddress): string | undefined {
  const value = entry.address.trim();
  return addressUri(entry.network, value) ?? (looksLikeAddress(value) ? value : undefined);
}
