import type { ReactNode } from 'react';
import { Icon, type IconName } from './Icon';
import styles from './EmptyState.module.css';

export interface EmptyStateProps {
  icon: IconName;
  title: ReactNode;
  children?: ReactNode;
  /** The next step, usually a Button. */
  action?: ReactNode;
}

export function EmptyState({ icon, title, children, action }: EmptyStateProps) {
  return (
    <div className={styles.empty}>
      <span className={styles.icon}>
        <Icon name={icon} size={28} />
      </span>
      <h2 className={styles.title}>{title}</h2>
      {children && <p className={styles.body}>{children}</p>}
      {action && <div className={styles.action}>{action}</div>}
    </div>
  );
}
