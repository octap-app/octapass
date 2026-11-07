import { describe, expect, it, vi } from 'vitest';
import { dataUrlBytes, PendingScans, scanImage, scanTab, type TabCapture } from './qr';

const LINK = 'otpauth://totp/GitHub:octo?secret=JBSWY3DPEHPK3PXP&issuer=GitHub';
const SCREENSHOT = `data:image/png;base64,${btoa('screenshot')}`;

function tabs(active = true): TabCapture & { captureVisibleTab: ReturnType<typeof vi.fn> } {
  return {
    get: vi.fn(async () => ({ windowId: 7, active })),
    captureVisibleTab: vi.fn(async () => SCREENSHOT),
  };
}

/** Reads "QR codes" from the bytes as text, like the core would from a real image. */
const read = (bytes: Uint8Array) => {
  const text = new TextDecoder().decode(bytes);
  if (text === 'svg') throw new Error('invalid_image');
  return text === 'screenshot' ? [LINK] : text ? [text] : [];
};

describe('QR codes from pages', () => {
  it('reads a screenshot of the tab when it is the one shown in its window', async () => {
    const capture = tabs();
    expect(await scanTab(capture, read, 3)).toEqual([LINK]);
    expect(capture.captureVisibleTab).toHaveBeenCalledWith(7, { format: 'png' });
    const hidden = tabs(false);
    expect(await scanTab(hidden, read, 3)).toEqual([]);
    expect(hidden.captureVisibleTab).not.toHaveBeenCalled();
  });

  it('reads data: images as they are, anything else from the screenshot, never downloading', async () => {
    const capture = tabs();
    const inline = `data:image/png;base64,${btoa('otpauth://totp/Inline?secret=A')}`;
    expect(await scanImage(capture, read, inline, 3)).toEqual(['otpauth://totp/Inline?secret=A']);
    expect(capture.captureVisibleTab).not.toHaveBeenCalled();
    expect(await scanImage(capture, read, 'https://example.com/qr.png?secret=JBSWY3DPEHPK3PXP', 3)).toEqual([LINK]);
    expect(await scanImage(capture, read, `data:image/svg+xml;base64,${btoa('svg')}`, 3)).toEqual([LINK]);
    expect(await scanImage(capture, read, 'https://example.com/qr.png', undefined)).toEqual([]);
  });

  it('decodes data URLs', () => {
    expect([...dataUrlBytes('data:image/png;base64,AAEC/w==')]).toEqual([0, 1, 2, 255]);
  });

  it('keeps the image menu’s scan for the popup, once', async () => {
    const pending = new PendingScans();
    expect(pending.has()).toBe(false);
    pending.start(Promise.resolve([LINK]));
    expect(pending.has()).toBe(true);
    expect(await pending.take()).toEqual([LINK]);
    expect(await pending.take()).toBeUndefined();
    pending.start(Promise.reject(new Error('no tab')));
    expect(await pending.take()).toEqual([]);
  });
});
