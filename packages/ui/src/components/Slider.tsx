import { useId, type CSSProperties, type ReactNode } from 'react';
import styles from './Slider.module.css';

export interface SliderProps {
  label: ReactNode;
  value: number;
  min: number;
  max: number;
  step?: number;
  onChange: (value: number) => void;
  /** Spoken value, e.g. "20 characters". */
  valueText?: string;
}

export function Slider({ label, value, min, max, step = 1, onChange, valueText }: SliderProps) {
  const id = useId();
  const fill = ((value - min) / (max - min)) * 100;
  return (
    <div className={styles.slider}>
      <div className={styles.head}>
        <label htmlFor={id}>{label}</label>
        <output htmlFor={id} className={styles.value}>
          {value}
        </output>
      </div>
      <input
        id={id}
        type="range"
        min={min}
        max={max}
        step={step}
        value={value}
        aria-valuetext={valueText}
        style={{ '--fill': `${fill}%` } as CSSProperties}
        onChange={(e) => onChange(Number(e.target.value))}
      />
    </div>
  );
}
