import { Button, IconButton, Switch, TextField, useToast } from '@octapass/ui';
import type { EquivalentDomains } from '@octapass/vault-client';
import { useEffect, useState } from 'react';
import { useService } from '../../app/ServiceContext';
import { Alert } from '../../components/Alert';
import { t } from '../../i18n';
import { errorMessage } from '../../lib/errors';
import { Section } from './SettingsPage';
import styles from './SettingsPage.module.css';

const splitDomains = (text: string) => text.split(/[\s,]+/).filter(Boolean);

/**
 * Sites that share one sign-in. The list is an encrypted vault item, so it follows the account; what
 * a domain may be (never a public suffix like `co.uk`) is decided by the core when saving.
 */
export function EquivalentDomainsSection() {
  const service = useService();
  const toast = useToast();
  const [list, setList] = useState<EquivalentDomains>();
  const [rows, setRows] = useState<string[]>([]);
  const [rejected, setRejected] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let live = true;
    service.equivalentDomains?.().then(
      (next) => {
        if (!live) return;
        setList(next);
        setRows(next.groups.map((group) => group.join(', ')));
      },
      () => undefined,
    );
    return () => {
      live = false;
    };
  }, [service]);

  if (!service.saveEquivalentDomains || !list) return null;

  async function save(excludedDefaults = list!.excludedDefaults) {
    setBusy(true);
    try {
      const saved = await service.saveEquivalentDomains!({ groups: rows.map(splitDomains), excludedDefaults });
      setList(saved);
      setRows(saved.groups.map((group) => group.join(', ')));
      setRejected(saved.rejected);
      toast({ message: t('equivalent.saved'), tone: 'success' });
    } catch (e) {
      toast({ message: errorMessage(e), tone: 'danger' });
    } finally {
      setBusy(false);
    }
  }

  return (
    <Section id="equivalent-domains" title={t('equivalent.title')} description={t('equivalent.help')}>
      {rows.map((row, i) => (
        <div key={i} className={styles.row}>
          <TextField
            label={t('equivalent.group', { n: i + 1 })}
            hideLabel
            mono
            spellCheck={false}
            autoComplete="off"
            placeholder="example.com, example.org"
            value={row}
            onChange={(e) => setRows((all) => all.map((one, at) => (at === i ? e.target.value : one)))}
            actions={<IconButton size="sm" icon="close" label={t('equivalent.removeGroup', { n: i + 1 })} onClick={() => setRows((all) => all.filter((_, at) => at !== i))} />}
          />
        </div>
      ))}
      <div className={styles.row}>
        <Button variant="ghost" size="sm" icon="plus" onClick={() => setRows((all) => [...all, ''])}>
          {t('equivalent.addGroup')}
        </Button>
        <Button size="sm" busy={busy} onClick={() => void save()}>
          {t('common.save')}
        </Button>
      </div>
      {rejected.length > 0 && <Alert>{t('equivalent.rejected', { domains: rejected.join(', ') })}</Alert>}
      {list.defaults.map((group) => {
        const name = group[0]!;
        const on = !list.excludedDefaults.includes(name);
        return (
          <div key={name} className={styles.row}>
            <Switch
              label={<bdi dir="ltr">{group.slice(0, 3).join(', ') + (group.length > 3 ? ' …' : '')}</bdi>}
              checked={on}
              disabled={busy}
              onChange={(next) => void save(next ? list.excludedDefaults.filter((one) => one !== name) : [...list.excludedDefaults, name])}
            />
          </div>
        );
      })}
    </Section>
  );
}
