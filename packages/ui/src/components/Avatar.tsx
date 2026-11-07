import { useState, type CSSProperties, type Ref } from 'react';
import styles from './Avatar.module.css';

/** A stable hue per name, so an item keeps its colour across sessions. */
export function hueFor(name: string): number {
  let hash = 0;
  for (const char of name.toLowerCase()) hash = (hash * 31 + char.codePointAt(0)!) >>> 0;
  return hash % 360;
}

export interface AvatarProps {
  name: string;
  size?: 'sm' | 'md' | 'lg' | 'xl';
  /** The website's icon. The coloured initial shows until it loads, and if it fails. */
  src?: string;
  className?: string;
  ref?: Ref<HTMLSpanElement>;
}

export function Avatar({ name, size = 'md', src, className, ref }: AvatarProps) {
  const letter = Array.from(name.trim())[0]?.toUpperCase() ?? '?';
  const [failed, setFailed] = useState<string>();
  const [loaded, setLoaded] = useState<string>();
  const showImage = src !== undefined && failed !== src;
  return (
    <span
      ref={ref}
      className={[styles.avatar, styles[size], showImage && loaded === src && styles.icon, className].filter(Boolean).join(' ')}
      style={{ '--h': hueFor(name) } as CSSProperties}
      aria-hidden="true"
    >
      {showImage && loaded === src ? null : letter}
      {showImage && (
        <img
          src={src}
          alt=""
          className={loaded === src ? styles.image : styles.loading}
          onLoad={() => setLoaded(src)}
          onError={() => setFailed(src)}
          draggable={false}
        />
      )}
    </span>
  );
}
