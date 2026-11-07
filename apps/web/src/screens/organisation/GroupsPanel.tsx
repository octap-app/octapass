import { Button, IconButton, Select, TextField } from '@octapass/ui';
import type { OrgGroup, OrgMember } from '@octapass/vault-client';
import { useState, type FormEvent } from 'react';
import { ConfirmDialog } from '../../components/ConfirmDialog';
import { t } from '../../i18n';
import { useAction } from '../../lib/useAction';
import { useOrganisationData, useOrganisations } from '../../lib/useOrganisation';
import { Section } from '../settings/SettingsPage';
import styles from '../sharing/Sharing.module.css';

/** Groups are lists of people. Linking one to a vault happens under Vaults. */
export function GroupsPanel() {
  const organisations = useOrganisations()!;
  const { data: groups } = useOrganisationData((o) => o.listOrgGroups());
  const { data: people } = useOrganisationData((o) => o.listOrgMembers());
  const { busy, run } = useAction();
  const [name, setName] = useState('');
  const [deleting, setDeleting] = useState<OrgGroup>();

  function create(event: FormEvent) {
    event.preventDefault();
    if (!name.trim()) return;
    void run('create', () => organisations.createOrgGroup(name.trim()), t('organisation.groupCreated')).then((done) => done && setName(''));
  }

  if (!groups || !people) return <p className={styles.empty}>{t('common.loading')}</p>;
  return (
    <Section id="groups" title={t('organisation.tabGroups')} description={t('organisation.groupsHelp')}>
      {groups.length === 0 && <p className={styles.empty}>{t('organisation.noGroups')}</p>}
      {groups.map((group) => (
        <Group key={group.id} group={group} members={people.members} onDelete={() => setDeleting(group)} />
      ))}
      <form className={styles.panel} onSubmit={create}>
        <h3>{t('organisation.newGroup')}</h3>
        <TextField label={t('organisation.groupName')} hint={t('organisation.nameHint')} maxLength={64} value={name} onChange={(e) => setName(e.target.value)} />
        <Button type="submit" size="sm" busy={busy === 'create'}>
          {t('organisation.createGroup')}
        </Button>
      </form>
      <ConfirmDialog
        open={deleting !== undefined}
        onClose={() => setDeleting(undefined)}
        title={t('organisation.deleteGroupTitle', { name: deleting?.name ?? '' })}
        confirmLabel={t('organisation.deleteGroup')}
        onConfirm={() => organisations.deleteOrgGroup(deleting!.id)}
      >
        {t('organisation.deleteGroupBody')}
      </ConfirmDialog>
    </Section>
  );
}

function Group({ group, members, onDelete }: { group: OrgGroup; members: OrgMember[]; onDelete: () => void }) {
  const organisations = useOrganisations()!;
  const { busy, run } = useAction();
  const inGroup = members.filter((member) => group.members.includes(member.accountId));
  const others = members.filter((member) => !group.members.includes(member.accountId));

  return (
    <div className={styles.panel}>
      <div className={styles.person}>
        <h3 className={styles.who}>{group.name}</h3>
        <div className={styles.controls}>
          <IconButton icon="trash" tone="danger" label={t('organisation.deleteGroupNamed', { name: group.name })} onClick={onDelete} />
        </div>
      </div>
      <ul className={styles.list} aria-label={group.name}>
        {inGroup.map((member) => (
          <li key={member.accountId} className={styles.person}>
            <span className={styles.who}>{member.email}</span>
            <div className={styles.controls}>
              <IconButton
                icon="close"
                label={t('organisation.removeFromGroup', { email: member.email, name: group.name })}
                disabled={busy === member.accountId}
                onClick={() => void run(member.accountId, () => organisations.removeOrgGroupMember(group.id, member.accountId))}
              />
            </div>
          </li>
        ))}
      </ul>
      {others.length > 0 && (
        <Select
          label={t('organisation.addToGroup', { name: group.name })}
          size="sm"
          value=""
          options={[{ value: '', label: t('organisation.chooseMember') }, ...others.map((member) => ({ value: member.accountId, label: member.email }))]}
          onChange={(e) => {
            const accountId = e.target.value;
            if (accountId) void run(accountId, () => organisations.addOrgGroupMember(group.id, accountId));
          }}
        />
      )}
    </div>
  );
}
