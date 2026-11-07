import styles from './Spinner.module.css';

export function Spinner({ size = 18, className }: { size?: number; className?: string }) {
  return (
    <svg className={[styles.spinner, className].filter(Boolean).join(' ')} width={size} height={size} viewBox="0 0 24 24" aria-hidden="true">
      <circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" strokeOpacity="0.25" strokeWidth="2.5" />
      <path d="M21 12a9 9 0 0 0-9-9" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" />
    </svg>
  );
}
