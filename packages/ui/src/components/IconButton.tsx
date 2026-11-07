import type { ButtonHTMLAttributes } from 'react';
import { Icon, type IconName } from './Icon';
import styles from './IconButton.module.css';

export interface IconButtonProps extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'children'> {
  icon: IconName;
  /** Required: icon-only buttons need an accessible name. Also shown as the tooltip. */
  label: string;
  size?: 'sm' | 'md';
  tone?: 'default' | 'active' | 'danger';
}

export function IconButton({ icon, label, size = 'md', tone = 'default', className, type = 'button', ...rest }: IconButtonProps) {
  return (
    <button type={type} aria-label={label} title={label} className={[styles.button, styles[size], styles[tone], className].filter(Boolean).join(' ')} {...rest}>
      <Icon name={icon} size={size === 'sm' ? 16 : 20} />
    </button>
  );
}
