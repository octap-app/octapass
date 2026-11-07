import { IconButton } from '@octapass/ui';
import { t } from '../../i18n';
import { useCopy } from '../../lib/clipboard';
import styles from './local.module.css';

/** The backup recovery code, in groups that are easy to copy out by hand. */
export function RecoveryCode({ code }: { code: string }) {
  const copy = useCopy();
  return (
    <div className={styles.code}>
      <span className="mono">{code}</span>
      <IconButton icon="copy" size="sm" label={t('copy.action', { what: t('localVault.recoveryCode') })} onClick={() => void copy(code, t('localVault.recoveryCode'))} />
    </div>
  );
}
