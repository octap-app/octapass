import { useId } from 'react';
import markDark from '../assets/logo-mark-dark.svg?raw';
import mark from '../assets/logo-mark.svg?raw';
import tile from '../assets/logo-tile.svg?raw';
import styles from './Logo.module.css';

export interface LogoProps {
  variant?: 'mark' | 'tile';
  size?: number;
  className?: string;
}

/** The brand logo, inlined from brand/. Gradient ids are made unique so several logos can share a page. */
export function Logo({ variant = 'tile', size = 32, className }: LogoProps) {
  const id = useId().replace(/[^a-zA-Z0-9-]/g, '');
  const prepare = (svg: string) =>
    svg
      .replaceAll('op-g', `op-g-${id}`)
      .replaceAll('op-t', `op-t-${id}`)
      .replace('width="64" height="64"', `width="${size}" height="${size}" aria-hidden="true" focusable="false"`)
      .replace(/<title>.*?<\/title>/, '');

  if (variant === 'tile') {
    return <span className={[styles.logo, className].filter(Boolean).join(' ')} dangerouslySetInnerHTML={{ __html: prepare(tile) }} />;
  }
  return (
    <span className={[styles.logo, styles.themed, className].filter(Boolean).join(' ')}>
      <span className={styles.light} dangerouslySetInnerHTML={{ __html: prepare(mark) }} />
      <span className={styles.dark} dangerouslySetInnerHTML={{ __html: prepare(markDark).replaceAll(`op-g-${id}`, `op-gd-${id}`) }} />
    </span>
  );
}
