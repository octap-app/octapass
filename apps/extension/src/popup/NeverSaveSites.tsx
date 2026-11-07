import { Button } from '@octapass/ui';
import { Row, Section } from '@octapass/web/src/screens/settings/SettingsPage';
import { useEffect, useState } from 'react';
import type { NeverSaveEntry } from '../background/neverSave';
import { tx } from '../i18n';
import { useExtension } from './ExtensionContext';

/** The sites where the user answered "Never for this site" to a save prompt, each with a way to undo it. */
export function NeverSaveSites() {
  const { api } = useExtension();
  const [entries, setEntries] = useState<NeverSaveEntry[]>();

  useEffect(() => {
    void api.neverSaveSites().then(setEntries);
  }, [api]);

  async function remove({ site, kind }: NeverSaveEntry) {
    await api.removeNeverSave(site, kind);
    setEntries(await api.neverSaveSites());
  }

  return (
    <Section id="never-save" title={tx('neverSave.title')} description={tx('neverSave.help')}>
      {entries?.length === 0 && <Row label={tx('neverSave.none')} />}
      {entries?.map((entry) => (
        <Row key={`${entry.site} ${entry.kind}`} label={<bdi dir="ltr">{entry.site}</bdi>} description={tx(`neverSave.${entry.kind}`)}>
          <Button variant="secondary" size="sm" icon="trash" aria-label={tx('neverSave.removeWhat', { site: entry.site, kind: tx(`neverSave.${entry.kind}`) })} onClick={() => void remove(entry)}>
            {tx('neverSave.remove')}
          </Button>
        </Row>
      ))}
    </Section>
  );
}
