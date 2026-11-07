// Chrome sends runtime messages as JSON, so bytes, Blobs and Files would arrive as `{}`. These
// helpers turn them into tagged base64url strings on the way out and back on the way in. Firefox
// uses structured clone, but the same encoding works there too.

import { base64UrlDecode, base64UrlEncode } from '@octapass/vault-client';

const TAG = '__octapassWire';

type Tagged =
  | { [TAG]: 'bytes'; data: string }
  | { [TAG]: 'blob'; data: string; type: string }
  | { [TAG]: 'file'; data: string; type: string; name: string; lastModified: number };

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null) return false;
  const proto = Object.getPrototypeOf(value) as unknown;
  return proto === Object.prototype || proto === null;
}

async function blobData(blob: Blob): Promise<string> {
  return base64UrlEncode(new Uint8Array(await blob.arrayBuffer()));
}

/** A JSON-safe copy of `value`. */
export async function encodeWire(value: unknown): Promise<unknown> {
  if (value instanceof Uint8Array) return { [TAG]: 'bytes', data: base64UrlEncode(value) } satisfies Tagged;
  if (value instanceof ArrayBuffer) return { [TAG]: 'bytes', data: base64UrlEncode(new Uint8Array(value)) } satisfies Tagged;
  if (typeof File !== 'undefined' && value instanceof File) {
    return { [TAG]: 'file', data: await blobData(value), type: value.type, name: value.name, lastModified: value.lastModified } satisfies Tagged;
  }
  if (value instanceof Blob) return { [TAG]: 'blob', data: await blobData(value), type: value.type } satisfies Tagged;
  if (Array.isArray(value)) return Promise.all(value.map(encodeWire));
  if (isPlainObject(value)) {
    const entries = await Promise.all(Object.entries(value).map(async ([key, v]) => [key, await encodeWire(v)] as const));
    return Object.fromEntries(entries);
  }
  return value;
}

/** Undoes `encodeWire`. */
export function decodeWire(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(decodeWire);
  if (!isPlainObject(value)) return value;
  const tagged = value as Partial<Tagged>;
  switch (tagged[TAG]) {
    case 'bytes':
      return base64UrlDecode(tagged.data!);
    case 'blob':
      return new Blob([base64UrlDecode(tagged.data!)], { type: tagged.type });
    case 'file': {
      const file = tagged as Extract<Tagged, { [TAG]: 'file' }>;
      return new File([base64UrlDecode(file.data)], file.name, { type: file.type, lastModified: file.lastModified });
    }
    default:
      return Object.fromEntries(Object.entries(value).map(([key, v]) => [key, decodeWire(v)]));
  }
}
