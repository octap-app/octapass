import { deviceMethodHelp, deviceMethodName } from './deviceUnlock';

describe('device unlock labels', () => {
  it('uses the name people know on each platform', () => {
    expect(deviceMethodName('mac')).toBe('Touch ID');
    expect(deviceMethodName('windows')).toBe('Windows Hello');
    expect(deviceMethodName('ios')).toBe('Face ID or passcode');
    expect(deviceMethodName('other')).toBe('your device');
    expect(deviceMethodHelp('other')).toMatch(/fingerprint, face or password/);
  });
});
