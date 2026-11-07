import type { KeyLogCheck } from '@octapass/vault-client';
import { t } from '../i18n';
import { Alert } from './Alert';

/** What the key log says about keys found by email, before anything is shared with them. */
export function KeyLogNote({ check }: { check?: KeyLogCheck | undefined }) {
  if (check === 'verified') return <Alert tone="success">{t('keyLog.verifiedHelp')}</Alert>;
  if (check === 'notLogged') return <Alert tone="info">{t('keyLog.notLoggedHelp')}</Alert>;
  if (check === 'failed') return <Alert>{t('keyLog.failedHelp')}</Alert>;
  return null;
}
