// Wi-Fi networks (plan 01, Wi-Fi): the `WIFI:` QR format, the security types, and the move of
// older Wi-Fi items (a password item with an "SSID" field) to the `wifi` type.

import type { CustomField, Item, ItemDraft, ItemSummary, LoginDetails, VaultService, WifiDetails, WifiEapMethod, WifiPhase2, WifiSecurity, WifiSighting } from './types';
import { SCHEMA_VERSION } from './types';

export const WIFI_SECURITIES: readonly WifiSecurity[] = ['wpa2', 'wpa2Wpa3', 'wpa3', 'wpaWpa2', 'wpa', 'wep', 'open', 'wpa2Enterprise', 'wpa3Enterprise'];
export const WIFI_EAP_METHODS: readonly WifiEapMethod[] = ['peap', 'ttls', 'tls', 'pwd', 'leap', 'fast'];
export const WIFI_PHASE2: readonly WifiPhase2[] = ['mschapv2', 'gtc', 'pap', 'chap', 'mschap'];

export function isEnterprise(security: WifiSecurity): boolean {
  return security === 'wpa2Enterprise' || security === 'wpa3Enterprise';
}

/** Open networks have no password; every other kind does. */
export function hasPassword(security: WifiSecurity): boolean {
  return security !== 'open';
}

/** Reads a security type as people, routers and other apps write it ("WPA2", "wpa2-personal", "None", "SAE"). */
export function parseWifiSecurity(text: string | undefined, password?: string): WifiSecurity | undefined {
  const v = (text ?? '').toLowerCase().replace(/[\s_./-]+/g, '');
  if (!v) return password ? 'wpa2' : 'open';
  if (['none', 'open', 'nopass', 'unsecured', 'unsecure', 'nosecurity'].includes(v)) return 'open';
  if (v.includes('enterprise') || v.includes('eap') || v.includes('8021x')) return v.includes('3') ? 'wpa3Enterprise' : 'wpa2Enterprise';
  if (v.startsWith('wep')) return 'wep';
  if (v === 'sae' || v.startsWith('wpa3')) return 'wpa3';
  if (v.startsWith('wpa2wpa3') || v.startsWith('wpa2sae') || v.startsWith('wpa3wpa2')) return 'wpa2Wpa3';
  if (v.startsWith('wpawpa2') || v.startsWith('wpa1wpa2')) return 'wpaWpa2';
  if (v.startsWith('wpa2') || v === 'psk' || v === 'wpapsk' || v === 'wpa2psk') return 'wpa2';
  if (v.startsWith('wpa')) return 'wpa';
  return undefined;
}

/** A new Wi-Fi item's details. */
export function emptyWifi(): WifiDetails {
  return { schemaVersion: SCHEMA_VERSION, ssid: '', security: 'wpa2' };
}

// `\`, `;`, `,`, `:` and `"` are escaped with a backslash in WIFI: fields.
const escape = (value: string) => value.replace(/([\\;,:"])/g, '\\$1');

/**
 * The `WIFI:` text phone cameras join from. Every WPA kind is `T:WPA`, which every camera reads (the
 * device works out WPA2 or WPA3 itself). Enterprise networks have none: each person signs in.
 */
export function wifiQrText(wifi: Pick<WifiDetails, 'ssid' | 'security' | 'password' | 'hidden'>): string | undefined {
  if (!wifi.ssid || isEnterprise(wifi.security)) return undefined;
  const type = wifi.security === 'open' ? 'nopass' : wifi.security === 'wep' ? 'WEP' : 'WPA';
  let text = `WIFI:T:${type};S:${escape(wifi.ssid)};`;
  if (type !== 'nopass' && wifi.password) text += `P:${escape(wifi.password)};`;
  if (wifi.hidden) text += 'H:true;';
  return `${text};`;
}

/** What a scanned `WIFI:` code says. */
export type ScannedWifi = Pick<WifiDetails, 'ssid' | 'security' | 'password' | 'hidden' | 'eapMethod' | 'phase2' | 'identity' | 'username'>;

/** Reads a scanned `WIFI:` code (with the `WPA2-EAP` fields Android writes for Enterprise networks). */
export function parseWifiQr(text: string): ScannedWifi | undefined {
  if (!text.startsWith('WIFI:')) return undefined;
  const fields = new Map<string, string>();
  let key = '';
  let value = '';
  let inValue = false;
  for (let i = 5; i < text.length; i++) {
    const c = text[i]!;
    if (c === '\\' && i + 1 < text.length) {
      value += text[++i];
    } else if (!inValue && c === ':') {
      key = value;
      value = '';
      inValue = true;
    } else if (c === ';') {
      if (inValue) fields.set(key.toUpperCase(), value);
      key = '';
      value = '';
      inValue = false;
    } else {
      value += c;
    }
  }
  const ssid = fields.get('S');
  if (!ssid) return undefined;
  const password = fields.get('P') || undefined;
  const type = fields.get('T')?.toUpperCase();
  // `T:WPA` covers the whole WPA family; WPA2 is what a router most likely uses.
  const security = type === 'WPA' ? 'wpa2' : (parseWifiSecurity(type, password) ?? 'wpa2');
  const scanned: ScannedWifi = { ssid, security };
  if (password && security !== 'open') scanned.password = password;
  if (fields.get('H')?.toLowerCase() === 'true') scanned.hidden = true;
  if (isEnterprise(security)) {
    const eap = fields.get('E')?.toLowerCase() as WifiEapMethod | undefined;
    const phase2 = fields.get('PH2')?.toLowerCase() as WifiPhase2 | undefined;
    if (eap && WIFI_EAP_METHODS.includes(eap)) scanned.eapMethod = eap;
    if (phase2 && WIFI_PHASE2.includes(phase2)) scanned.phase2 = phase2;
    if (fields.get('I')) scanned.username = fields.get('I');
    if (fields.get('A')) scanned.identity = fields.get('A');
  }
  return scanned;
}

/** A new Wi-Fi item for a network, named after it. */
export function wifiDraft(network: Partial<WifiDetails> & Pick<WifiDetails, 'ssid'>, vaultId: string): ItemDraft {
  const details: WifiDetails = { ...emptyWifi(), ...network, schemaVersion: SCHEMA_VERSION };
  if (!hasPassword(details.security)) delete details.password;
  return { vaultId, overview: { schemaVersion: SCHEMA_VERSION, type: 'wifi', title: network.ssid, subtitle: network.ssid }, details };
}

// ---------- Older Wi-Fi items ----------

// Before the `wifi` type, a network was a password item with an "SSID" field (and maybe "Security"
// and "Hidden"), which scanning a Wi-Fi QR code made; importers wrote the same for Wi-Fi entries.
const SSID_LABELS = ['ssid', 'network', 'network name', 'wi-fi network', 'wifi network', 'wi-fi name', 'wifi name'];
const SECURITY_LABELS = ['security', 'security type', 'wi-fi security', 'encryption'];
const HIDDEN_LABELS = ['hidden', 'hidden network'];

const labelIs = (field: CustomField, labels: string[]) => labels.includes(field.label.trim().toLowerCase());

/**
 * The item as a `wifi` item, when it's an older Wi-Fi item: a password item or a login with a network
 * name field and nothing only a login holds (website, one-time code, passkey, recovery; for a login,
 * a username). Nothing is lost: other fields stay as fields, and a security type it can't read stays
 * as one too.
 */
export function upgradeLegacyWifi(item: Item): ItemDraft | undefined {
  const { type, urls, ...overview } = item.overview;
  if (type !== 'password' && type !== 'login') return undefined;
  const { username, totp, passkeys, recovery, customFields = [], password, ...rest } = item.details as LoginDetails;
  if ((type === 'login' && username) || totp || passkeys?.length || recovery || urls?.some((u) => u.trim())) return undefined;
  const ssidField = customFields.find((f) => labelIs(f, SSID_LABELS) && f.value.trim());
  if (!ssidField) return undefined;

  const ssid = ssidField.value.trim();
  const securityField = customFields.find((f) => labelIs(f, SECURITY_LABELS));
  const hiddenField = customFields.find((f) => labelIs(f, HIDDEN_LABELS));
  const security = parseWifiSecurity(securityField?.value.trim(), password);
  const others = customFields.filter((f) => f !== ssidField && f !== hiddenField && (f !== securityField || !security));

  const details: WifiDetails = { ...rest, schemaVersion: SCHEMA_VERSION, ssid, security: security ?? (password ? 'wpa2' : 'open') };
  if (password) details.password = password;
  if (hiddenField && ['yes', 'true', '1', 'on'].includes(hiddenField.value.trim().toLowerCase())) details.hidden = true;
  // A password item's username isn't an Enterprise sign-in: it stays a field.
  if (username) others.unshift({ label: 'Username', value: username, hidden: false });
  if (others.length) details.customFields = others;

  return {
    id: item.id,
    vaultId: item.vaultId,
    revision: item.revision,
    overview: { ...overview, type: 'wifi', subtitle: ssid },
    details,
  };
}

/** Logins and password items that could be older Wi-Fi items, from their list rows. */
function mayBeLegacyWifi(summary: ItemSummary): boolean {
  if (summary.type === 'password') return true;
  return summary.type === 'login' && !summary.urls?.some((u) => u.trim()) && !summary.hasTotp && !summary.hasPasskey;
}

/**
 * Moves older Wi-Fi items in writable vaults to the `wifi` type, and returns how many. `checked`
 * remembers the rows already looked at (by id and change time), so later runs only open new ones.
 */
export async function upgradeLegacyWifiItems(service: Pick<VaultService, 'listVaults' | 'listItems' | 'getItem' | 'saveItem'>, checked = new Map<string, string>()): Promise<number> {
  const vaults = await service.listVaults();
  const writable = new Set(vaults.filter((v) => v.role !== 'read' && !v.untrusted).map((v) => v.id));
  const rows = (await service.listItems()).filter((s) => mayBeLegacyWifi(s) && writable.has(s.vaultId) && checked.get(s.id) !== s.updatedAt);
  let upgraded = 0;
  for (const row of rows) {
    checked.set(row.id, row.updatedAt);
    try {
      const draft = upgradeLegacyWifi(await service.getItem(row.id));
      if (!draft) continue;
      await service.saveItem(draft);
      upgraded++;
    } catch {
      // Gone, changed meanwhile or offline: the next run tries again.
      checked.delete(row.id);
    }
  }
  return upgraded;
}

// ---------- Marks in the list ----------

/** The Wi-Fi rows' network names are their subtitles. */
export function wifiSsid(summary: Pick<ItemSummary, 'type' | 'subtitle'>): string | undefined {
  return summary.type === 'wifi' ? summary.subtitle : undefined;
}

/** The sighting of each network in range, by name. */
export function sightingsByName(sightings: readonly WifiSighting[]): Map<string, WifiSighting> {
  const byName = new Map<string, WifiSighting>();
  for (const s of sightings) {
    const before = byName.get(s.ssid);
    if (!before || before.signal < s.signal) byName.set(s.ssid, s);
  }
  return byName;
}

/** Signal strength as bars, 1 to 4, the way the system shows it. */
export function signalBars(signal: number): 1 | 2 | 3 | 4 {
  return signal >= 75 ? 4 : signal >= 50 ? 3 : signal >= 25 ? 2 : 1;
}

/**
 * The networks the device is on or sees first (connected, then strongest), the rest after in their
 * own order. Stable: rows the device doesn't see keep the order they came in.
 */
export function inRangeFirst<T extends Pick<ItemSummary, 'type' | 'subtitle'>>(items: readonly T[], sightings: ReadonlyMap<string, WifiSighting>, connected?: string): T[] {
  const rank = (item: T) => {
    const ssid = wifiSsid(item);
    if (!ssid) return -1;
    if (ssid === connected) return 101;
    return sightings.get(ssid)?.signal ?? -1;
  };
  return items
    .map((item, index) => ({ item, index, rank: rank(item) }))
    .sort((a, b) => b.rank - a.rank || a.index - b.index)
    .map((entry) => entry.item);
}
