import type { Address, ApiCredentialDetails, CardDetails, CertificateDetails, CustomDetails, CustomField, CustomTemplateDetails, DocumentDetails, KeyItemDetails, EnvironmentDetails, IdentityDetails, Item, ItemDetails, LoginDetails, SecureNoteDetails, SshKeyDetails, Vault, WalletAddress, WifiDetails } from '../types';
import { HIDDEN_ITEM_TYPES } from '../items';
import { ITEM_FIELDS } from '../itemFields';
import { authorizedKeysLine } from '../sshKeys';
import { toCsv } from './csv';

/**
 * Attachments are listed by name, type and size; the files aren't in the export, and their keys
 * would open nothing outside this item, so they're left out.
 */
function exportedDetails(details: ItemDetails): unknown {
  const attachments = (details as { attachments?: { id: string; name: string; type: string; size: number }[] }).attachments;
  if (!attachments) return details;
  return { ...details, attachments: attachments.map(({ id, name, type, size }) => ({ id, name, type, size })) };
}

/** The full-fidelity format, minus attachment files. The caller leaves out trashed items. */
export function exportJson(vaults: Vault[], items: Item[], now: Date = new Date()): string {
  return JSON.stringify(
    {
      format: 'octapass-export',
      version: 1,
      exportedAt: now.toISOString(),
      vaults: vaults.map(({ id, name, type }) => ({ id, name, type })),
      // The dashboard's settings stay out of every format built on this one: importing them would
      // turn email breach alerts on for another account. Usage stats name items by their ids here,
      // which an import gives new ones, so they'd mean nothing there.
      items: items.filter((item) => item.overview.type !== 'healthSettings' && item.overview.type !== 'usageStats').map(({ id, vaultId, createdAt, updatedAt, overview, details }) => ({
        id,
        vaultId,
        createdAt,
        updatedAt,
        overview,
        details: exportedDetails(details),
      })),
    },
    null,
    2,
  );
}

const CSV_HEADER = ['vault', 'type', 'title', 'url', 'username', 'password', 'totp', 'notes', 'tags', 'favorite'];

function lines(fields: [label: string, value: string | undefined][]): string[] {
  return fields.flatMap(([label, value]) => (value ? [`${label}: ${value}`] : []));
}

function addressText(address: Address | undefined): string | undefined {
  if (!address) return undefined;
  const cityLine = [address.postalCode, address.city, address.region].filter(Boolean).join(' ');
  return [address.line1, address.line2, cityLine, address.country].filter(Boolean).join(', ') || undefined;
}

/** Fields without a CSV column go into the notes as "Label: value" lines, ahead of the item's own notes. */
function notesOf(item: Item): string {
  const parts = (summary: string[], notes: string | undefined) => [...summary, notes].filter(Boolean).join('\n');
  switch (item.overview.type) {
    case 'card': {
      const d = item.details as CardDetails;
      const summary = lines([
        ['Cardholder', d.cardholder],
        ['Number', d.number],
        ['Expiry', d.expiry],
        ['CVV', d.cvv],
        ['PIN', d.pin],
        ['Brand', d.brand],
      ]);
      return parts(summary, d.notes);
    }
    case 'identity': {
      const d = item.details as IdentityDetails;
      const summary = lines([
        ['Name', [d.firstName, d.lastName].filter(Boolean).join(' ')],
        ['Email', d.email],
        ['Phone', d.phone],
        ['Address', addressText(d.address)],
        ['Birth date', d.birthDate],
      ]);
      return parts(summary, d.notes);
    }
    case 'secureNote':
      return (item.details as SecureNoteDetails).notes;
    case 'document': {
      const d = item.details as DocumentDetails;
      return parts(lines((d.attachments ?? []).map((file) => ['File', file.name])), d.notes);
    }
    case 'login':
    case 'password': {
      const d = item.details as LoginDetails;
      return parts(lines((d.customFields ?? []).map((f) => [f.label, f.value])), d.notes);
    }
    case 'wifi': {
      const d = item.details as WifiDetails;
      const yes = (flag: boolean | undefined) => (flag ? 'Yes' : undefined);
      const summary = lines([
        ['SSID', d.ssid],
        ['Security', d.security],
        ['Hidden', yes(d.hidden)],
        ['EAP method', d.eapMethod],
        ['Phase 2', d.phase2],
        ['Identity', d.identity],
        ['Server domain', d.serverDomain],
        ['Sign-in page', yes(d.captivePortal)],
        ['Managed', yes(d.managed)],
        ['Personal Hotspot', yes(d.hotspot)],
        ...(d.customFields ?? []).map((f): [string, string] => [f.label, f.value]),
      ]);
      return parts(summary, d.notes);
    }
    case 'environment': {
      const d = item.details as EnvironmentDetails;
      return parts(
        lines([
          ['Project', d.project],
          ['Stage', d.stage],
          ...d.variables.map((variable): [string, string] => [variable.key, variable.value]),
        ]),
        d.notes,
      );
    }
    case 'certificate': {
      const d = item.details as CertificateDetails;
      return parts(
        lines([
          ['Certificate', d.certificate],
          ['Chain', d.chain],
          ['Private key', d.privateKey],
          ...(d.customFields ?? []).map((f): [string, string] => [f.label, f.value]),
        ]),
        d.notes,
      );
    }
    case 'key': {
      const d = item.details as KeyItemDetails;
      return parts(
        lines([
          ['Kind', d.kind],
          ['Algorithm', d.algorithm],
          ['Key ID', d.keyId],
          ['Fingerprint', d.fingerprint],
          ['User ID', d.userId],
          ['Public key', d.publicKey],
          ['JWKS', d.jwks],
          ['Private key', d.privateKey],
          ['Secret', d.secret],
          ['JWK', d.jwk],
          ['Passphrase', d.passphrase],
          ...(d.customFields ?? []).map((f): [string, string] => [f.label, f.value]),
        ]),
        d.notes,
      );
    }
    case 'sshKey': {
      const d = item.details as SshKeyDetails;
      const summary = lines([
        ['Key type', d.keyType],
        ['Fingerprint', d.fingerprint],
        ['Public key', authorizedKeysLine(d)],
        ['Passphrase', d.passphrase],
        ...(d.customFields ?? []).map((f): [string, string] => [f.label, f.value]),
      ]);
      return parts([...summary, ...(d.privateKey ? [d.privateKey.trim()] : [])], d.notes);
    }
    case 'apiCredential': {
      const d = item.details as ApiCredentialDetails;
      // The extension saves pasted keys as `credential`/`hostname`; the editor uses `key`/`host`.
      const summary = lines([
        ['Type', d.credentialType],
        ['Username', d.username],
        ['Key', d.key ?? d.credential],
        ['Secret', d.secret],
        ['Host', d.host ?? d.hostname],
        ['Expiry', d.expiryDate],
        ...(d.customFields ?? []).map((f): [string, string] => [f.label, f.value]),
      ]);
      return parts(summary, d.notes);
    }
    case 'bankAccount':
    case 'softwareLicense':
    case 'idDocument':
    case 'database':
    case 'cryptoWallet': {
      const d = item.details as unknown as Record<string, string> & { customFields?: CustomField[]; addresses?: WalletAddress[]; notes?: string };
      const summary = lines([
        ...ITEM_FIELDS[item.overview.type].map((field): [string, string | undefined] => [field.key, d[field.key]]),
        ...(d.addresses ?? []).map((entry): [string, string] => [entry.network, entry.address]),
        ...(d.customFields ?? []).map((f): [string, string] => [f.label, f.value]),
      ]);
      return parts(summary, d.notes);
    }
    case 'custom': {
      const d = item.details as CustomDetails;
      return parts(lines(d.fields.map((f): [string, string] => [f.label, f.value])), d.notes);
    }
    case 'customTemplate':
      return parts(lines((item.details as CustomTemplateDetails).fields.map((f): [string, string] => [f.label, f.kind])), undefined);
    case 'maskedEmailProvider':
    case 'healthSettings':
    case 'equivalentDomains':
    case 'usageStats':
      return '';
  }
}

/**
 * A lossy, spreadsheet-friendly export: one row per item. JSON is the full one. Masked email
 * provider tokens and equivalent domains are settings, not items another app could import, so only
 * JSON has them.
 */
export function exportCsv(vaults: Vault[], items: Item[]): string {
  const vaultNames = new Map(vaults.map((v) => [v.id, v.name]));
  const rows = items.filter((item) => !HIDDEN_ITEM_TYPES.has(item.overview.type)).map((item) => {
    const { overview } = item;
    // Wi-Fi networks share the username (Enterprise) and password columns.
    const login = overview.type === 'login' || overview.type === 'password' || overview.type === 'wifi' ? (item.details as LoginDetails) : undefined;
    return [
      vaultNames.get(item.vaultId) ?? '',
      overview.type,
      overview.title,
      (overview.urls ?? []).join(' '),
      login?.username ?? '',
      login?.password ?? '',
      login?.totp ?? '',
      notesOf(item),
      (overview.tags ?? []).join(','),
      overview.favorite ? 'true' : 'false',
    ];
  });
  return toCsv([CSV_HEADER, ...rows]);
}
