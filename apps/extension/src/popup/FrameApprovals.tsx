import { Button } from '@octapass/ui';
import { Row, Section } from '@octapass/web/src/screens/settings/SettingsPage';
import { useEffect, useState } from 'react';
import type { FrameApproval } from '../background/frames';
import { tx } from '../i18n';
import { useExtension } from './ExtensionContext';

const hostOf = (origin: string) => {
  try {
    return new URL(origin).host;
  } catch {
    return origin;
  }
};

/** The frames from other sites the user allowed from the inline menu, each with a way to take it back. */
export function FrameApprovals() {
  const { api } = useExtension();
  const [approvals, setApprovals] = useState<FrameApproval[]>();

  useEffect(() => {
    void api.frameApprovals().then(setApprovals);
  }, [api]);

  async function remove({ site, origin }: FrameApproval) {
    await api.removeFrameApproval(site, origin);
    setApprovals(await api.frameApprovals());
  }

  return (
    <Section id="frames" title={tx('frames.title')} description={tx('frames.help')}>
      {approvals?.length === 0 && <Row label={tx('frames.none')} />}
      {approvals?.map((approval) => (
        <Row key={`${approval.site} ${approval.origin}`} label={hostOf(approval.origin)} description={tx('frames.inside', { site: approval.site })}>
          <Button variant="secondary" size="sm" icon="trash" aria-label={tx('frames.removeWhat', { frame: hostOf(approval.origin), site: approval.site })} onClick={() => void remove(approval)}>
            {tx('frames.remove')}
          </Button>
        </Row>
      ))}
    </Section>
  );
}
