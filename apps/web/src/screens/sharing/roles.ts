import type { SelectOption } from '@octapass/ui';
import type { VaultRole } from '@octapass/vault-client';
import { t, type MessageKey } from '../../i18n';

const ROLES: VaultRole[] = ['owner', 'manage', 'write', 'read'];

export const roleLabel = (role: VaultRole) => t(`roles.${role}` as MessageKey);

export const canManage = (role: VaultRole | undefined) => role === 'owner' || role === 'manage';

/** Managers add and remove people below owner; only owners hand out, change or remove `owner` (plan 15). */
export function canChangeMember(myRole: VaultRole | undefined, theirRole: VaultRole): boolean {
  return myRole === 'owner' || (myRole === 'manage' && theirRole !== 'owner');
}

export function roleOptions(myRole: VaultRole | undefined): SelectOption[] {
  return ROLES.filter((role) => myRole === 'owner' || role !== 'owner').map((role) => ({ value: role, label: `${roleLabel(role)}: ${t(`roles.${role}Help` as MessageKey)}` }));
}
