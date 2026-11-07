import { emptyDraft, type CryptoWalletDetails, type CustomDetails, type ItemDraft } from '@octapass/vault-client';
import { describe, expect, it } from 'vitest';
import { cleanDraft, validateDraft } from './editorModel';
import { fieldsFromTemplate, templateFields } from './TypedItems';

function draft(type: ItemDraft['overview']['type'], details: Record<string, unknown>): ItemDraft {
  const empty = emptyDraft(type, 'v');
  return { ...empty, overview: { ...empty.overview, title: ' T ' }, details: { ...empty.details, ...details } as ItemDraft['details'] };
}

describe('saving the new item types', () => {
  it('reports bad values under their fields', () => {
    const errors = validateDraft(draft('bankAccount', { iban: 'DE00', swift: 'x' }));
    expect(errors).toEqual({ iban: 'validation.iban', swift: 'validation.swift' });
    expect(validateDraft(draft('database', { port: '99999' }))).toEqual({ port: 'validation.port' });
    expect(validateDraft(draft('idDocument', { expiryDate: 'soon' }))).toEqual({ expiryDate: 'validation.date' });
  });

  it('refuses a seed phrase typed where an address goes', () => {
    const addresses = [{ network: 'bitcoin', address: 'legal winner thank year wave sausage worth useful' }];
    expect(validateDraft(draft('cryptoWallet', { addresses }))).toEqual({ 'addresses.0': 'validation.walletAddress' });
  });

  it('keeps secrets exactly as typed and trims the rest', () => {
    const cleaned = cleanDraft(draft('cryptoWallet', { walletName: ' Cold ', seedPhrase: ' abandon ability ', passphrase: ' p ' }));
    expect(cleaned.overview.title).toBe('T');
    expect(cleaned.details).toMatchObject({ walletName: 'Cold', seedPhrase: ' abandon ability ', passphrase: ' p ' });
  });

  it('takes the list subtitle from a field that isn’t secret', () => {
    expect(cleanDraft(draft('bankAccount', { bankName: 'Example Bank', pin: '1234' })).overview.subtitle).toBe('Example Bank');
    expect(cleanDraft(draft('database', { host: 'db.example.com', password: 'x' })).overview.subtitle).toBe('db.example.com');
    expect(cleanDraft(draft('cryptoWallet', { seedPhrase: 'abandon' })).overview.subtitle).toBeUndefined();
  });

  it('drops address rows left empty and keeps fields from a newer client', () => {
    const cleaned = cleanDraft(draft('cryptoWallet', { addresses: [{ network: 'bitcoin', address: '' }], futureField: 1 }));
    expect((cleaned.details as CryptoWalletDetails).addresses).toBeUndefined();
    expect(cleaned.details).toMatchObject({ futureField: 1 });
  });

  it('drops custom rows with neither label nor value, and keeps values as typed', () => {
    const fields = [{ label: ' PIN ', value: ' 12 ', kind: 'hidden' }, { label: '', value: '', kind: 'text' }];
    expect((cleanDraft(draft('custom', { fields })).details as CustomDetails).fields).toEqual([{ label: 'PIN', value: ' 12 ', kind: 'hidden' }]);
  });
});

describe('templates', () => {
  it('never take an item’s values', () => {
    const saved = templateFields([{ label: ' PIN ', value: '1234', kind: 'hidden' }, { label: '', value: 'stray', kind: 'text' }]);
    expect(saved).toEqual([{ label: 'PIN', kind: 'hidden' }]);
    expect(JSON.stringify(saved)).not.toContain('1234');
  });

  it('become empty fields on a new item', () => {
    expect(fieldsFromTemplate({ fields: [{ label: 'Member', kind: 'text' }] })).toEqual([{ label: 'Member', kind: 'text', value: '' }]);
  });
});
