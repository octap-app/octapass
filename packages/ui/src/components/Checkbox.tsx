import type { InputHTMLAttributes, ReactNode } from 'react';
import { Icon } from './Icon';
import styles from './Checkbox.module.css';

export interface CheckboxProps extends Omit<InputHTMLAttributes<HTMLInputElement>, 'type'> {
  label: ReactNode;
}

export function Checkbox({ label, className, ...input }: CheckboxProps) {
  return (
    <label className={[styles.checkbox, className].filter(Boolean).join(' ')}>
      <input type="checkbox" className={styles.input} {...input} />
      <span className={styles.box} aria-hidden="true">
        <Icon name="check" size={14} strokeWidth={2.6} />
      </span>
      <span>{label}</span>
    </label>
  );
}
