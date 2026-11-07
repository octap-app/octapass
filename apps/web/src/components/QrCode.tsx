import qrcode from 'qrcode-generator';
import { useMemo } from 'react';

/** Renders a QR code as one SVG path, crisp on screen and in print. */
export function QrCode({ value, size = 160, label }: { value: string; size?: number; label: string }) {
  const { path, count } = useMemo(() => {
    const qr = qrcode(0, 'M');
    qr.addData(value);
    qr.make();
    const n = qr.getModuleCount();
    let d = '';
    for (let row = 0; row < n; row++) {
      for (let col = 0; col < n; col++) if (qr.isDark(row, col)) d += `M${col} ${row}h1v1h-1z`;
    }
    return { path: d, count: n };
  }, [value]);

  return (
    <svg viewBox={`-2 -2 ${count + 4} ${count + 4}`} width={size} height={size} role="img" aria-label={label} shapeRendering="crispEdges">
      <rect x="-2" y="-2" width={count + 4} height={count + 4} fill="#fff" />
      <path d={path} fill="#0b1220" />
    </svg>
  );
}
