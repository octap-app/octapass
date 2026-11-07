import { Icon } from '@octapass/ui';
import type { ReactNode } from 'react';
import styles from './Alert.module.css';

/** An inline message. Errors use role="alert" so they're read out as soon as they appear. */
export function Alert({ tone = 'danger', children, action }: { tone?: 'danger' | 'info' | 'success' | 'warn'; children: ReactNode; action?: ReactNode }) {
  return (
    <div className={[styles.alert, styles[tone]].join(' ')} role={tone === 'danger' ? 'alert' : 'status'}>
      <Icon name={tone === 'success' ? 'check' : tone === 'info' ? 'info' : 'alert'} size={18} />
      <div className={styles.text}>{children}</div>
      {action}
    </div>
  );
}
