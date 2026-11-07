import { isSmartList, type ItemFilter, type ItemType, type SmartList } from '@octapass/vault-client';

/**
 * The list a URL shows: /items/all, /items/favorites, /items/pinned, /items/codes, /items/v-<vaultId>,
 * /items/login, /items/trash … The lists with an order of their own (`SmartList`) are
 * /items/created, /items/frequent, /items/used and /items/changed.
 */
export type Scope =
  | { kind: 'all' | 'favorites' | 'pinned' | 'passkeys' | 'codes' | 'trash' }
  | { kind: 'smart'; list: SmartList }
  | { kind: 'vault'; vaultId: string }
  | { kind: 'type'; type: ItemType };

export const ITEM_TYPES: ItemType[] = ['login', 'password', 'card', 'identity', 'secureNote', 'wifi', 'sshKey', 'certificate', 'key', 'document', 'environment', 'bankAccount', 'idDocument', 'cryptoWallet', 'apiCredential', 'database', 'softwareLicense', 'custom', 'customTemplate'];

export function parseScope(param: string | undefined): Scope {
  if (param === 'favorites' || param === 'pinned' || param === 'passkeys' || param === 'codes' || param === 'trash') return { kind: param };
  if (isSmartList(param)) return { kind: 'smart', list: param };
  if (param?.startsWith('v-')) return { kind: 'vault', vaultId: param.slice(2) };
  if (ITEM_TYPES.includes(param as ItemType)) return { kind: 'type', type: param as ItemType };
  return { kind: 'all' };
}

export function scopeFilter(scope: Scope): ItemFilter {
  switch (scope.kind) {
    case 'favorites':
      return { favorites: true };
    case 'pinned':
      return { pinned: true };
    case 'passkeys':
      return { passkeys: true };
    case 'codes':
      return { totp: true };
    case 'trash':
      return { trash: true };
    case 'vault':
      return { vaultId: scope.vaultId };
    case 'type':
      return { type: scope.type };
    // Smart lists start from every item and put them in their own order (`useScopeItems`).
    default:
      return {};
  }
}
