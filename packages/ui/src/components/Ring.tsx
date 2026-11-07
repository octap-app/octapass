import { useId, type ReactNode } from 'react';
import styles from './Ring.module.css';

export interface RingProps {
  /** 0–1. */
  value: number;
  size?: number;
  stroke?: number;
  tone?: 'free' | 'trust' | 'gradient' | 'warn' | 'danger';
  /** Content centred inside the ring, e.g. a score. */
  children?: ReactNode;
  /** Animate changes smoothly (a countdown ticks linearly; a score eases in). */
  transition?: 'linear' | 'ease';
  className?: string;
}

/** A progress ring for health scores and one-time code countdowns. Decorative: pair it with text. */
export function Ring({ value, size = 40, stroke = 4, tone = 'free', children, transition = 'ease', className }: RingProps) {
  const gradientId = useId();
  const r = 18 - stroke / 2;
  const clamped = Math.min(1, Math.max(0, value));
  return (
    <span className={[styles.ring, className].filter(Boolean).join(' ')} style={{ inlineSize: size, blockSize: size }}>
      <svg viewBox="0 0 36 36" width={size} height={size} aria-hidden="true">
        {tone === 'gradient' && (
          <defs>
            <linearGradient id={gradientId} x1="0" y1="0" x2="1" y2="1">
              <stop offset="0" stopColor="#2456f0" />
              <stop offset="1" stopColor="#10b77f" />
            </linearGradient>
          </defs>
        )}
        <circle cx="18" cy="18" r={r} className={styles.track} strokeWidth={stroke} />
        <circle
          cx="18"
          cy="18"
          r={r}
          pathLength={100}
          strokeWidth={stroke}
          className={[styles.fill, styles[tone], styles[transition]].join(' ')}
          stroke={tone === 'gradient' ? `url(#${gradientId})` : undefined}
          strokeDasharray={`${clamped * 100} 100`}
        />
      </svg>
      {children !== undefined && <span className={styles.label}>{children}</span>}
    </span>
  );
}
