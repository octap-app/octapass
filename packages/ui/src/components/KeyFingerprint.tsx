import styles from './KeyFingerprint.module.css';

export interface KeyFingerprintProps {
  /** Six groups of four digits, separated by spaces. */
  digits: string;
  emoji?: { emoji: string; name: string }[];
  /** Accessible name for the whole fingerprint, e.g. "Fingerprint of sam@example.com". */
  label: string;
  /** What the emoji row is, for screen readers. */
  emojiLabel?: string;
  size?: 'sm' | 'md';
}

/** An account's key fingerprint, laid out to be read aloud and compared group by group. */
export function KeyFingerprint({ digits, emoji, label, emojiLabel, size = 'md' }: KeyFingerprintProps) {
  const groups = digits.split(/\s+/).filter(Boolean);
  const names = emoji?.map((e) => e.name).join(', ');
  return (
    <figure className={[styles.fingerprint, styles[size]].join(' ')} aria-label={label}>
      <ol className={styles.groups}>
        {groups.map((group, i) => (
          <li key={i}>{group}</li>
        ))}
      </ol>
      {emoji && emoji.length > 0 && (
        <p className={styles.emoji} aria-label={emojiLabel ? `${emojiLabel}: ${names}` : names}>
          {emoji.map((e, i) => (
            <span key={i} title={e.name} aria-hidden="true">
              {e.emoji}
            </span>
          ))}
        </p>
      )}
    </figure>
  );
}
