import { Button, Switch, TextField } from '@octapass/ui';
import type { OrgPolicies } from '@octapass/vault-client';
import { useState } from 'react';
import { t } from '../../i18n';
import { useAction } from '../../lib/useAction';
import { useOrganisations } from '../../lib/useOrganisation';
import { Section } from '../settings/SettingsPage';
import styles from '../sharing/Sharing.module.css';

function numberOrUndefined(text: string): number | undefined {
  const value = Number(text);
  return text.trim() && Number.isInteger(value) && value > 0 ? value : undefined;
}

/** Rules for members. What the server enforces and what only the apps apply are kept apart, plainly. */
export function PoliciesPanel({ policies }: { policies: OrgPolicies }) {
  const organisations = useOrganisations()!;
  const { busy, run } = useAction();
  const [draft, setDraft] = useState(policies);
  const set = (change: Partial<OrgPolicies>) => setDraft({ ...draft, ...change });

  return (
    <>
      <Section id="server-policies" title={t('organisation.policiesServer')} description={t('organisation.policiesServerHelp')}>
        <Switch label={t('organisation.requireTwoStep')} description={t('organisation.requireTwoStepHelp')} checked={draft.requireTwoStep} onChange={(requireTwoStep) => set({ requireTwoStep })} />
        <Switch label={t('organisation.requireSso')} description={t('organisation.requireSsoHelp')} checked={draft.requireSso} onChange={(requireSso) => set({ requireSso })} />
        {draft.requireSso && (
          <div className={styles.panel}>
            <TextField
              label={t('organisation.ssoMaxAge')}
              hint={t('organisation.ssoMaxAgeHelp')}
              inputMode="numeric"
              value={String(draft.ssoMaxAgeHours)}
              onChange={(e) => set({ ssoMaxAgeHours: Math.max(0, Number.parseInt(e.target.value, 10) || 0) })}
            />
          </div>
        )}
        <Switch label={t('organisation.disableShareLinks')} description={t('organisation.disableShareLinksHelp')} checked={draft.disableShareLinks} onChange={(disableShareLinks) => set({ disableShareLinks })} />
        <Switch label={t('organisation.disableEmergency')} description={t('organisation.disableEmergencyHelp')} checked={draft.disableEmergencyAccess} onChange={(disableEmergencyAccess) => set({ disableEmergencyAccess })} />
      </Section>
      <Section id="client-policies" title={t('organisation.policiesClient')} description={t('organisation.policiesClientHelp')}>
        <Switch label={t('organisation.disableExport')} description={t('organisation.disableExportHelp')} checked={draft.disableExport} onChange={(disableExport) => set({ disableExport })} />
        <div className={styles.panel}>
          <TextField
            label={t('organisation.maxAutoLock')}
            hint={t('organisation.maxAutoLockHelp')}
            inputMode="numeric"
            value={draft.maxAutoLockMinutes === undefined ? '' : String(draft.maxAutoLockMinutes)}
            onChange={(e) => set({ maxAutoLockMinutes: numberOrUndefined(e.target.value) })}
          />
          <TextField
            label={t('organisation.minPassword')}
            hint={t('organisation.minPasswordHelp')}
            inputMode="numeric"
            value={draft.minPasswordLength === undefined ? '' : String(draft.minPasswordLength)}
            onChange={(e) => set({ minPasswordLength: numberOrUndefined(e.target.value) })}
          />
        </div>
      </Section>
      <Button busy={busy === 'save'} onClick={() => void run('save', () => organisations.setOrgPolicies(draft), t('organisation.policiesSaved'))}>
        {t('organisation.savePolicies')}
      </Button>
    </>
  );
}
