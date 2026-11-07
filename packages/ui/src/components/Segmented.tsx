import { useId, type ReactNode } from 'react';
import styles from './Segmented.module.css';

export interface SegmentedOption<T extends string> {
  value: T;
  label: ReactNode;
  /** The label's language when it differs from the page's, like a language's own name. */
  lang?: string;
}

export interface SegmentedProps<T extends string> {
  label: string;
  options: SegmentedOption<T>[];
  value: T;
  onChange: (value: T) => void;
  block?: boolean;
}

/** A radio group drawn as a segmented control: arrow keys move between options natively. */
export function Segmented<T extends string>({ label, options, value, onChange, block }: SegmentedProps<T>) {
  const name = useId();
  return (
    <div role="radiogroup" aria-label={label} className={[styles.group, block && styles.block].filter(Boolean).join(' ')}>
      {options.map((option) => (
        <label key={option.value} className={styles.option}>
          <input type="radio" name={name} value={option.value} checked={option.value === value} onChange={() => onChange(option.value)} />
          <span lang={option.lang}>{option.label}</span>
        </label>
      ))}
    </div>
  );
}
