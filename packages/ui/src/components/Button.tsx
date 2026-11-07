import type { ButtonHTMLAttributes, ReactNode } from 'react';
import { Icon, type IconName } from './Icon';
import { Spinner } from './Spinner';
import styles from './Button.module.css';

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'ghost' | 'danger';
  size?: 'sm' | 'md' | 'lg';
  icon?: IconName;
  /** Shows a spinner and blocks clicks, keeping the label so the width doesn't jump. */
  busy?: boolean;
  block?: boolean;
  children?: ReactNode;
}

export function Button({ variant = 'primary', size = 'md', icon, busy, block, className, children, disabled, type = 'button', ...rest }: ButtonProps) {
  const classes = [styles.button, styles[variant], styles[size], block && styles.block, busy && styles.busy, className].filter(Boolean).join(' ');
  return (
    <button type={type} className={classes} disabled={disabled || busy} aria-busy={busy || undefined} {...rest}>
      {busy && <Spinner className={styles.spinner} size={size === 'sm' ? 14 : 18} />}
      <span className={styles.content}>
        {icon && <Icon name={icon} size={size === 'sm' ? 16 : 18} />}
        {children}
      </span>
    </button>
  );
}
