import { IconButton } from '@octapass/ui';
import { t } from '@octapass/web/src/i18n';
import { useCopy } from '@octapass/web/src/lib/clipboard';
import { tx } from '../../i18n';
import styles from './local.module.css';

/** The backup recovery code, in groups that are easy to copy out by hand. */
export function RecoveryCode({ code }: { code: string }) {
  const copy = useCopy();
  return (
    <div className={styles.code}>
      <span className="mono">{code}</span>
      <IconButton icon="copy" size="sm" label={t('copy.action', { what: tx('local.recoveryCode') })} onClick={() => void copy(code, tx('local.recoveryCode'))} />
    </div>
  );
}
