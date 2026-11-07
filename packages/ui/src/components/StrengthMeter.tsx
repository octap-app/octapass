import styles from './StrengthMeter.module.css';

export interface StrengthMeterProps {
  /** 0–4, from the estimator. */
  score: number;
  label: string;
  hint?: string;
  /** Hide the bar when there's nothing to rate yet. */
  empty?: boolean;
}

export function StrengthMeter({ score, label, hint, empty }: StrengthMeterProps) {
  return (
    <div className={styles.meter} data-score={empty ? 'empty' : score}>
      <div className={styles.bars} aria-hidden="true">
        {[0, 1, 2, 3].map((i) => (
          <span key={i} className={!empty && i < Math.max(1, score) ? styles.on : undefined} />
        ))}
      </div>
      <p className={styles.text} aria-live="polite">
        <strong>{label}</strong>
        {hint && <span> {hint}</span>}
      </p>
    </div>
  );
}
