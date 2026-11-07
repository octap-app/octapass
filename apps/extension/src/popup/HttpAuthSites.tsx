import { Button } from '@octapass/ui';
import { Row, Section } from '@octapass/web/src/screens/settings/SettingsPage';
import { useEffect, useState } from 'react';
import type { HttpAuthApproval } from '../background/httpAuth';
import { tx } from '../i18n';
import { useExtension } from './ExtensionContext';

const hostOf = (origin: string) => {
  try {
    return new URL(origin).host;
  } catch {
    return origin;
  }
};

/** Safari has no `webRequest.onAuthRequired`, so its own sign-in dialog shows there. */
export const httpAuthSupported = () => Boolean((globalThis as { chrome?: typeof chrome }).chrome?.webRequest?.onAuthRequired);

/** The sites whose HTTP sign-in prompts the user let Octa Pass answer, each with a way to take it back. */
export function HttpAuthSites() {
  const { api } = useExtension();
  const [approvals, setApprovals] = useState<HttpAuthApproval[]>();

  useEffect(() => {
    void api.httpAuthApprovals().then(setApprovals);
  }, [api]);

  async function remove(origin: string) {
    await api.removeHttpAuthApproval(origin);
    setApprovals(await api.httpAuthApprovals());
  }

  return (
    <Section id="http-auth" title={tx('httpAuth.sitesTitle')} description={tx('httpAuth.sitesHelp')}>
      {approvals?.length === 0 && <Row label={tx('httpAuth.none')} />}
      {approvals?.map(({ origin }) => (
        <Row key={origin} label={hostOf(origin)}>
          <Button variant="secondary" size="sm" icon="trash" aria-label={tx('httpAuth.removeWhat', { host: hostOf(origin) })} onClick={() => void remove(origin)}>
            {tx('httpAuth.remove')}
          </Button>
        </Row>
      ))}
    </Section>
  );
}
