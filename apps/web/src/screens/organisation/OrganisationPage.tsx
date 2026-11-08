import { Button, EmptyState, Segmented, Spinner, TextField } from '@octapass/ui';
import type { Organisation, OrgInvitation, OrgPolicies } from '@octapass/vault-client';
import { useState, type FormEvent } from 'react';
import { Link } from 'react-router';
import { formatDate, t } from '../../i18n';
import { useAction } from '../../lib/useAction';
import { useOrganisationData, useOrganisations } from '../../lib/useOrganisation';
import { PageHeader } from '../PageHeader';
import { Row, Section } from '../settings/SettingsPage';
import settingsStyles from '../settings/SettingsPage.module.css';
import sharingStyles from '../sharing/Sharing.module.css';
import { AccessReview } from './AccessReview';
import { ActivityPanel } from './ActivityPanel';
import { GroupsPanel } from './GroupsPanel';
import { LeavePanel } from './LeavePanel';
import { MembersPanel } from './MembersPanel';
import { PoliciesPanel } from './PoliciesPanel';
import { ScimPanel } from './ScimPanel';
import { SsoPanel } from './SsoPanel';
import { VaultsPanel } from './VaultsPanel';

type Tab = 'members' | 'groups' | 'vaults' | 'policies' | 'sso' | 'scim' | 'activity';

/** Organisation: invitations, or the organisation itself; what shows depends on the member's role. */
export function OrganisationPage() {
  const organisations = useOrganisations();
  const { data } = useOrganisationData((o) => o.getOrganisation());

  if (!organisations) {
    return (
      <div className={settingsStyles.page}>
        <PageHeader title={t('organisation.title')} />
        <EmptyState icon="users" title={t('organisation.unavailable')} />
      </div>
    );
  }
  return (
    <div className={settingsStyles.page}>
      <PageHeader title={data?.organisation?.name ?? t('organisation.title')} subtitle={t('organisation.subtitle')} />
      <div className={settingsStyles.body}>
        {!data ? (
          <Spinner size={20} />
        ) : (
          <>
            {data.invitations.map((invitation) => (
              <Invitation key={invitation.id} invitation={invitation} joined={Boolean(data.organisation)} />
            ))}
            {data.organisation ? <Member organisation={data.organisation} /> : <Create />}
          </>
        )}
      </div>
    </div>
  );
}

function Create() {
  const organisations = useOrganisations()!;
  const { busy, run } = useAction();
  const [name, setName] = useState('');

  function submit(event: FormEvent) {
    event.preventDefault();
    if (name.trim()) void run('create', () => organisations.createOrganisation(name.trim()), t('organisation.created'));
  }

  return (
    <Section id="create" title={t('organisation.create')} description={t('organisation.createHelp')}>
      <form className={sharingStyles.panel} onSubmit={submit}>
        <TextField label={t('organisation.name')} hint={t('organisation.nameHint')} maxLength={64} value={name} onChange={(e) => setName(e.target.value)} />
        <Button type="submit" size="sm" busy={busy === 'create'}>
          {t('organisation.createAction')}
        </Button>
      </form>
    </Section>
  );
}

/** The rules a policy set brings, in words, for an invitee to read before accepting. */
export function policySummary(policies: OrgPolicies): string[] {
  const lines: string[] = [];
  if (policies.requireSso) lines.push(t('organisation.policySso'));
  if (policies.requireTwoStep) lines.push(t('organisation.policyTwoStep'));
  if (policies.disableShareLinks) lines.push(t('organisation.policyShareLinks'));
  if (policies.disableEmergencyAccess) lines.push(t('organisation.policyEmergency'));
  if (policies.disableExport) lines.push(t('organisation.policyExport'));
  if (policies.maxAutoLockMinutes) lines.push(t('organisation.policyAutoLock', { minutes: policies.maxAutoLockMinutes }));
  if (policies.minPasswordLength) lines.push(t('organisation.policyPassword', { length: policies.minPasswordLength }));
  return lines;
}

function Invitation({ invitation, joined }: { invitation: OrgInvitation; joined: boolean }) {
  const organisations = useOrganisations()!;
  const { busy, run } = useAction();
  const rules = policySummary(invitation.policies);

  return (
    <Section id={`invitation-${invitation.id}`} title={t('organisation.invitation', { organisation: invitation.orgName })} description={invitation.invitedBy ? t('organisation.invitedBy', { email: invitation.invitedBy }) : undefined}>
      <div className={sharingStyles.panel}>
        <p>{t('organisation.joinPrivacy')}</p>
        <p>{t('organisation.joinOwners')}</p>
        {rules.length > 0 && (
          <>
            <h3>{t('organisation.joinRules')}</h3>
            <ul>
              {rules.map((rule) => (
                <li key={rule}>{rule}</li>
              ))}
            </ul>
          </>
        )}
        {joined && <p>{t('organisation.oneAtATime')}</p>}
        <div className={sharingStyles.controls}>
          <Button variant="secondary" size="sm" disabled={busy !== undefined} onClick={() => void run('decline', () => organisations.declineOrgInvite(invitation.orgId, invitation.id), t('organisation.declined'))}>
            {t('organisation.decline')}
          </Button>
          <Button size="sm" disabled={joined} busy={busy === 'accept'} onClick={() => void run('accept', () => organisations.acceptOrgInvite(invitation.orgId, invitation.id), t('organisation.joined'))}>
            {t('organisation.accept')}
          </Button>
        </div>
      </div>
    </Section>
  );
}

function Member({ organisation }: { organisation: Organisation }) {
  const admin = organisation.role !== 'member';
  const owner = organisation.role === 'owner';
  const [tab, setTab] = useState<Tab>('members');
  const rules = policySummary(organisation.policies);

  const tabs: { value: Tab; label: string }[] = [
    { value: 'members', label: t('organisation.tabMembers') },
    { value: 'groups', label: t('organisation.tabGroups') },
    { value: 'vaults', label: t('organisation.tabVaults') },
    ...(owner
      ? [
          { value: 'policies' as const, label: t('organisation.tabPolicies') },
          { value: 'sso' as const, label: t('organisation.tabSso') },
          { value: 'scim' as const, label: t('organisation.tabScim') },
        ]
      : []),
    { value: 'activity', label: t('organisation.tabActivity') },
  ];

  return (
    <>
      {organisation.accessWithheld && (
        <Section id="withheld" title={t('organisation.withheldTitle')}>
          <Row label={t('organisation.withheldBody')}>
            <Link to="/settings">{t('organisation.withheldAction')}</Link>
          </Row>
        </Section>
      )}
      <AccessReview />
      <Section id="summary" title={t('organisation.about')}>
        <Row
          label={t('organisation.yourRole', { role: t(`organisation.role_${organisation.role}`) })}
          description={t('organisation.since', { date: formatDate(organisation.createdAt, 'long'), count: organisation.memberCount })}
        />
        {rules.length > 0 && !owner && (
          <div className={sharingStyles.panel}>
            <h3>{t('organisation.joinRules')}</h3>
            <ul>
              {rules.map((rule) => (
                <li key={rule}>{rule}</li>
              ))}
            </ul>
          </div>
        )}
      </Section>
      {admin && (
        <>
          <Segmented label={t('organisation.sections')} options={tabs} value={tab} onChange={setTab} />
          {tab === 'members' && <MembersPanel owner={owner} />}
          {tab === 'groups' && <GroupsPanel />}
          {tab === 'vaults' && <VaultsPanel owner={owner} />}
          {tab === 'policies' && owner && <PoliciesPanel policies={organisation.policies} />}
          {tab === 'sso' && owner && <SsoPanel policies={organisation.policies} />}
          {tab === 'scim' && owner && <ScimPanel />}
          {tab === 'activity' && <ActivityPanel />}
        </>
      )}
      <LeavePanel organisation={organisation} />
    </>
  );
}
