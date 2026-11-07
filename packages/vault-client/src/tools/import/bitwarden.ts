import type { CardDetails, CustomField, IdentityDetails } from '../../types';
import { clean, compact, ImportCollector, invalidFile, loginOrNote, overview, type ParsedImport } from './shared';

type Json = Record<string, unknown>;

const asObject = (value: unknown): Json | undefined =>
  typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Json) : undefined;
const asArray = (value: unknown): unknown[] => (Array.isArray(value) ? value : []);

const TYPE = { login: 1, secureNote: 2, card: 3, identity: 4 };
const FIELD_TYPE = { text: 0, hidden: 1, boolean: 2 };

function customFields(item: Json): CustomField[] {
  return asArray(item.fields).flatMap((raw) => {
    const field = asObject(raw);
    // Linked fields (type 3) point at another field and have no value of their own.
    if (!field || ![FIELD_TYPE.text, FIELD_TYPE.hidden, FIELD_TYPE.boolean].includes(field.type as number)) return [];
    const label = clean(field.name) ?? '';
    const value = typeof field.value === 'string' ? field.value : '';
    return label || value ? [{ label, value, hidden: field.type === FIELD_TYPE.hidden }] : [];
  });
}

/** Fields the Octa Pass type has no place for are kept as "Label: value" lines ahead of the notes. */
function notesWith(lines: [string, unknown][], notes: unknown): string | undefined {
  const extra = lines.flatMap(([label, value]) => {
    const text = clean(value);
    return text ? [`${label}: ${text}`] : [];
  });
  return clean([...extra, clean(notes)].filter(Boolean).join('\n'));
}

const fieldLines = (fields: CustomField[]): [string, string][] => fields.map((f) => [f.label || 'Field', f.value]);

function expiry(card: Json): string | undefined {
  const month = clean(card.expMonth);
  const year = clean(card.expYear);
  if (!month || !year || !/^\d{1,2}$/.test(month) || !/^\d{2,4}$/.test(year)) return undefined;
  return `${month.padStart(2, '0')}/${year.slice(-2)}`;
}

function lastFour(number: string | undefined): string | undefined {
  const digits = number?.replace(/\D/g, '');
  return digits && digits.length >= 4 ? `•••• ${digits.slice(-4)}` : undefined;
}

/** An unencrypted Bitwarden JSON export. */
export function parseBitwarden(text: string): ParsedImport {
  let data: Json | undefined;
  try {
    data = asObject(JSON.parse(text));
  } catch {
    invalidFile('This is not a Bitwarden JSON export: the file is not valid JSON.');
  }
  if (data?.encrypted === true || data?.passwordProtected === true) {
    invalidFile('This Bitwarden export is encrypted. Export again with the format ".json" rather than ".json (Encrypted)".');
  }
  if (!data || !Array.isArray(data.items)) invalidFile('This is not a Bitwarden JSON export: it has no items list.');

  const folders = new Map(
    asArray(data.folders).flatMap((raw) => {
      const folder = asObject(raw);
      const id = clean(folder?.id);
      const name = clean(folder?.name);
      return id && name ? [[id, name] as const] : [];
    }),
  );

  const out = new ImportCollector();
  let passkeys = 0;
  data.items.forEach((raw, index) => {
    const item = asObject(raw);
    const number = index + 1;
    if (!item) return out.skip(`Item ${number} skipped: not an item.`);
    const folder = folders.get(clean(item.folderId) ?? '');
    const common = {
      title: clean(item.name),
      tags: folder ? [folder] : [],
      favorite: item.favorite === true,
    };
    const fields = customFields(item);

    switch (item.type) {
      case TYPE.login: {
        const login = asObject(item.login) ?? {};
        if (asArray(login.fido2Credentials).length > 0) passkeys++;
        const parsed = loginOrNote({
          ...common,
          urls: asArray(login.uris).map((uri) => clean(asObject(uri)?.uri) ?? ''),
          username: clean(login.username),
          password: typeof login.password === 'string' ? login.password : undefined,
          totp: clean(login.totp),
          notes: clean(item.notes),
          customFields: fields,
        });
        return parsed ? out.add(parsed) : out.skip(`Item ${number} skipped: no URL, username, password or notes.`);
      }
      case TYPE.secureNote:
        return out.add({
          overview: overview('secureNote', common),
          details: { schemaVersion: 1, notes: notesWith(fieldLines(fields), item.notes) ?? '' },
        });
      case TYPE.card: {
        const card = asObject(item.card) ?? {};
        const details: CardDetails = compact({
          schemaVersion: 1,
          cardholder: clean(card.cardholderName),
          number: clean(card.number),
          expiry: expiry(card),
          cvv: clean(card.code),
          brand: clean(card.brand),
          notes: notesWith(fieldLines(fields), item.notes),
        });
        return out.add({ overview: overview('card', { ...common, subtitle: lastFour(details.number) }), details });
      }
      case TYPE.identity: {
        const identity = asObject(item.identity) ?? {};
        const address = compact({
          line1: clean(identity.address1),
          line2: clean([clean(identity.address2), clean(identity.address3)].filter(Boolean).join(', ')),
          city: clean(identity.city),
          region: clean(identity.state),
          postalCode: clean(identity.postalCode),
          country: clean(identity.country),
        });
        const details: IdentityDetails = compact({
          schemaVersion: 1,
          firstName: clean([clean(identity.firstName), clean(identity.middleName)].filter(Boolean).join(' ')),
          lastName: clean(identity.lastName),
          email: clean(identity.email),
          phone: clean(identity.phone),
          address: Object.keys(address).length > 0 ? address : undefined,
          notes: notesWith(
            [
              ['Company', identity.company],
              ['Username', identity.username],
              ['SSN', identity.ssn],
              ['Passport number', identity.passportNumber],
              ['Licence number', identity.licenseNumber],
              ...fieldLines(fields),
            ],
            item.notes,
          ),
        });
        return out.add({ overview: overview('identity', { ...common, subtitle: details.email }), details });
      }
      default:
        return out.skip(`Item ${number} skipped: this item type can't be imported yet.`);
    }
  });
  if (passkeys > 0) {
    out.warn(`Passkeys can't be imported yet: ${passkeys} ${passkeys === 1 ? 'login was' : 'logins were'} imported without one.`);
  }
  return out.finish();
}
