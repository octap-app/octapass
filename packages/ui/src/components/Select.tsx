import { useId, type ReactNode, type SelectHTMLAttributes } from 'react';
import styles from './Select.module.css';

export interface SelectOption {
  value: string;
  label: string;
  disabled?: boolean;
}

export interface SelectProps extends Omit<SelectHTMLAttributes<HTMLSelectElement>, 'children' | 'size'> {
  label: ReactNode;
  /** Visually hide the label but keep it for screen readers. */
  hideLabel?: boolean;
  hint?: ReactNode;
  options: SelectOption[];
  size?: 'sm' | 'md';
}

/** A native select, for the keyboard and screen reader behaviour browsers already get right. */
export function Select({ label, hideLabel, hint, options, size = 'md', id, className, ...select }: SelectProps) {
  const auto = useId();
  const selectId = id ?? auto;
  const hintId = hint ? `${selectId}-hint` : undefined;
  return (
    <div className={[styles.field, className].filter(Boolean).join(' ')}>
      <label htmlFor={selectId} className={hideLabel ? 'visually-hidden' : styles.label}>
        {label}
      </label>
      <select id={selectId} className={[styles.select, styles[size]].join(' ')} aria-describedby={hintId} {...select}>
        {options.map((option) => (
          <option key={option.value} value={option.value} disabled={option.disabled}>
            {option.label}
          </option>
        ))}
      </select>
      {hint && (
        <p id={hintId} className={styles.hint}>
          {hint}
        </p>
      )}
    </div>
  );
}
