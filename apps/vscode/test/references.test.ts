import { describe, expect, it } from 'vitest';
import type { ItemRef } from '../src/connect';
import { encodePart, fieldRows, reference } from '../src/references';

function item(vault: string, name: string, itemId: string, fields: string[] = ['password']): ItemRef {
  return { vault, item: name, itemId, type: 'login', fields: fields.map((field) => ({ name: field, secret: true })) };
}

describe('encodePart', () => {
  it('encodes only % and /, % first', () => {
    expect(encodePart('CI/CD')).toBe('CI%2FCD');
    expect(encodePart('100%')).toBe('100%25');
    expect(encodePart('a%2Fb')).toBe('a%252Fb');
    expect(encodePart('My Item: é')).toBe('My Item: é');
  });
});

describe('reference', () => {
  it('encodes each part on its own', () => {
    expect(reference('Work', 'Stripe', 'password')).toBe('octapass://Work/Stripe/password');
    expect(reference('A/B', 'C%D', 'E/F')).toBe('octapass://A%2FB/C%25D/E%2FF');
  });
});

describe('fieldRows', () => {
  it('gives one row per field', () => {
    const rows = fieldRows([item('Work', 'Stripe', 'id-1', ['username', 'password'])]);
    expect(rows.map((row) => row.reference)).toEqual([
      'octapass://Work/Stripe/username',
      'octapass://Work/Stripe/password',
    ]);
  });

  it('writes an id when two items in a vault share a name, whatever the case', () => {
    const rows = fieldRows([item('Work', 'Bank', 'id-1'), item('Work', 'BANK', 'id-2'), item('Home', 'Bank', 'id-3')]);
    expect(rows.map((row) => row.reference)).toEqual([
      'octapass://Work/id-1/password',
      'octapass://Work/id-2/password',
      'octapass://Home/Bank/password',
    ]);
    expect(rows[0]?.item).toBe('Bank');
  });

  it('writes an id for an item with no name, and shows it', () => {
    const [row] = fieldRows([item('Work', ' ', 'id-1')]);
    expect(row).toMatchObject({ item: 'id-1', reference: 'octapass://Work/id-1/password' });
  });

  it('leaves out a field no reference can name', () => {
    expect(fieldRows([item('Work', 'Stripe', 'id-1', ['', '  ', 'key'])]).map((row) => row.field)).toEqual(['key']);
  });
});
