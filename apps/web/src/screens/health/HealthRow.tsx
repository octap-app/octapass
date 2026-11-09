import { Avatar, Button, Icon } from '@octapass/ui';
import type { HealthEntry } from '@octapass/vault-client';
import { Link } from 'react-router';
import { t } from '../../i18n';
import styles from './HealthPage.module.css';

interface RowProps {
  entry: HealthEntry;
  tag?: string;
  tone?: 'danger' | 'warn';
  /** Offers "Change password": opens the site's page in a new tab and starts the generator here. */
  onChange?: () => void;
  onDismiss?: () => void;
}

/** One item in a check's list. It opens the item; its actions sit underneath. A warning about no item (an address) doesn't open anything. */
export function Row({ entry, tag, tone, onChange, onDismiss }: RowProps) {
  const actions = onChange || onDismiss;
  const content = (
    <>
      <Avatar name={entry.title} size="sm" />
      <span className={styles.rowText}>
        <b>{entry.itemId ? entry.title : <bdi dir="ltr">{entry.title}</bdi>}</b>
        {entry.subtitle && <small>{entry.subtitle}</small>}
      </span>
      {tag && <span className={[styles.tag, tone && styles[tone]].filter(Boolean).join(' ')}>{tag}</span>}
    </>
  );
  return (
    <li className={styles.rowLine}>
      {entry.itemId ? (
        <Link to={`/items/all/${entry.itemId}`} className={styles.row}>
          {content}
          <Icon name="chevronRight" size={16} className={styles.chev} />
        </Link>
      ) : (
        <div className={styles.row}>{content}</div>
      )}
      {actions && (
        <div className={styles.rowActions}>
          {onChange &&
            (entry.changePasswordUrl ? (
              // A plain link, so the new tab is the user's own click and gets no referrer.
              <a href={entry.changePasswordUrl} target="_blank" rel="noopener noreferrer" className={styles.changeLink} onClick={onChange}>
                <Icon name="external" size={14} />
                {t('health.change.action')}
              </a>
            ) : (
              <Button variant="ghost" size="sm" onClick={onChange}>
                {t('health.change.action')}
              </Button>
            ))}
          {onDismiss && (
            <Button variant="ghost" size="sm" onClick={onDismiss}>
              {t('health.dismiss')}
            </Button>
          )}
        </div>
      )}
    </li>
  );
}
