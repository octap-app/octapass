import type { OrganisationService, OrgPolicies } from '@octapass/vault-client';
import { useService } from '../app/ServiceContext';
import { useLive } from './useItems';

/** The service's organisation features, if it has them: hosts without a sync server account don't. */
export function useOrganisations(): OrganisationService | undefined {
  return useService().organisations;
}

/** Loads organisation data, again whenever sharing or organisations change. */
export function useOrganisationData<T>(load: (organisations: OrganisationService) => Promise<T>, deps: unknown[] = []): { data: T | undefined; error: unknown; retry: () => void } {
  const organisations = useOrganisations();
  return useLive(() => (organisations ? load(organisations) : new Promise<T>(() => undefined)), [organisations, ...deps], { sharing: true });
}

/**
 * The organisation's rules this app applies itself. A modified client can ignore them, and the
 * screens that show them say so. Offline or with no organisation, there are none.
 */
export function useClientPolicies(): Pick<OrgPolicies, 'maxAutoLockMinutes' | 'minPasswordLength'> {
  const { data } = useOrganisationData((o) => o.getOrganisation().catch(() => undefined));
  return data?.organisation?.policies ?? {};
}
