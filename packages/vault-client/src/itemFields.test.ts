import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { CUSTOM_FIELD_KINDS, customKindIsPlain, ITEM_FIELDS, isDate, isIban, isPort, isSecretKind, isSwift, SUBTITLE_KEYS, validateItemFields } from './itemFields';
import { emptyDetails, emptyDraft, matchesFilter, summarizeItem, withPasswordHistory } from './items';
import { addressQrText, addressUri, epcQrText, looksLikeAddress } from './paymentQr';
import type { Item, ItemDetails, TableItemType } from './types';

const vectors = (name: string) => JSON.parse(readFileSync(resolve(process.cwd(), '../../crates/octapass-core/tests/vectors', name), 'utf8'));

describe('the field table', () => {
  const shared = vectors('item-fields.json');

  it('is the core’s', () => {
    expect(ITEM_FIELDS).toEqual(shared.types);
    expect(CUSTOM_FIELD_KINDS).toEqual(shared.customKinds);
  });

  it('validates as the core does', () => {
    for (const { type, details, errors } of shared.validate) expect(validateItemFields(type, details)).toEqual(errors);
  });

  it('never takes a subtitle from a secret', () => {
    for (const [type, key] of Object.entries(SUBTITLE_KEYS)) {
      if (type === 'custom') continue;
      expect(isSecretKind(ITEM_FIELDS[type as TableItemType].find((field) => field.key === key)!.kind)).toBe(false);
    }
  });

  it('treats a custom field kind it doesn’t know as a secret', () => {
    expect(customKindIsPlain('text')).toBe(true);
    for (const kind of ['hidden', 'totp', 'multiline', 'quantumKey', '']) expect(customKindIsPlain(kind)).toBe(false);
  });

  it('checks values', () => {
    expect(isDate('2024-02-29')).toBe(true);
    expect(isDate('2023-02-29')).toBe(false);
    expect(isPort('65535')).toBe(true);
    expect(isPort('0')).toBe(false);
    expect(isSwift('COBADEFFXXX')).toBe(true);
    expect(isSwift('COBADEF')).toBe(false);
    expect(isIban('de89 3704 0044 0532 0130 00')).toBe(true);
    expect(isIban('DE89370400440532013001')).toBe(false);
    expect(isIban('JO94CBJO0010000000000131000302')).toBe(true);
  });
});

describe('payment QR codes', () => {
  const shared = vectors('payment-qr.json');

  it('match the core’s vectors', () => {
    for (const { text, ...payment } of shared.epc) expect(epcQrText(payment) ?? null).toBe(text);
    for (const { network, address, uri } of shared.address) expect(addressUri(network, address) ?? null).toBe(uri);
    for (const { address, ok } of shared.looksLikeAddress) expect(looksLikeAddress(address)).toBe(ok);
  });

  it('never put a seed phrase in a code', () => {
    const seed = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
    for (const network of ['bitcoin', 'ethereum', 'solana']) expect(addressQrText({ network, address: seed })).toBeUndefined();
  });

  it('fall back to the plain address on chains without a URI standard', () => {
    const address = '9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin';
    expect(addressQrText({ network: 'solana', address })).toBe(address);
    expect(addressQrText({ network: 'ethereum', address: `0x${'a'.repeat(40)}` })).toBe(`ethereum:0x${'a'.repeat(40)}`);
  });
});

function item(type: Item['overview']['type'], details: Record<string, unknown>): Item {
  return { id: 'i', vaultId: 'v', revision: 1, createdAt: '', updatedAt: '', overview: { schemaVersion: 1, type, title: 'T' }, details: { schemaVersion: 1, ...details } as ItemDetails };
}

describe('new item types', () => {
  it('start with an empty field list where they have one', () => {
    expect(emptyDetails('custom')).toEqual({ schemaVersion: 1, fields: [] });
    expect(emptyDetails('customTemplate')).toEqual({ schemaVersion: 1, fields: [] });
    expect(emptyDetails('bankAccount')).toEqual({ schemaVersion: 1 });
  });

  it('keep templates out of lists until they’re asked for', () => {
    const summary = summarizeItem(item('customTemplate', { fields: [] }));
    expect(matchesFilter(summary)).toBe(false);
    expect(matchesFilter(summary, { type: 'customTemplate' })).toBe(true);
    expect(matchesFilter(summarizeItem(item('custom', { fields: [] })))).toBe(true);
  });

  it('never search a seed phrase', () => {
    const summary = summarizeItem(item('cryptoWallet', { seedPhrase: 'abandon ability' }));
    expect(JSON.stringify(summary)).not.toContain('abandon');
  });

  it('keep a database’s old passwords', () => {
    const before = item('database', { password: 'old' });
    const next = withPasswordHistory(before, { ...emptyDraft('database', 'v'), details: { schemaVersion: 1, password: 'new' } }, new Date('2026-11-02T00:00:00Z'));
    expect((next.details as { passwordHistory?: unknown[] }).passwordHistory).toEqual([{ password: 'old', changedAt: '2026-11-02T00:00:00.000Z' }]);
  });
});
