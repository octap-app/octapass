import { DEFAULT_DEVICE_AUTH_SETTINGS, deviceAuthDecision, deviceAuthSettingKey, type DeviceAuthSettings } from './deviceAuth';

const settings = (patch: Partial<DeviceAuthSettings> = {}): DeviceAuthSettings => ({ ...DEFAULT_DEVICE_AUTH_SETTINGS, ...patch });

describe('deviceAuthDecision', () => {
  it('asks on app open and every fill by default', () => {
    expect(deviceAuthDecision('appOpen', { settings: settings(), osCredential: true })).toEqual({ required: true, lockless: false });
    expect(deviceAuthDecision('autofill', { settings: settings(), osCredential: true })).toEqual({ required: true, lockless: false });
  });

  it('lets autofill fill directly while unlocked when its own gate is off, but keeps app open gated', () => {
    const off = settings({ requireDeviceAuthOnAutofill: false });
    expect(deviceAuthDecision('autofill', { settings: off, osCredential: true })).toEqual({ required: false, lockless: false });
    expect(deviceAuthDecision('appOpen', { settings: off, osCredential: true })).toEqual({ required: true, lockless: false });
  });

  it('follows the app-open setting independently', () => {
    const off = settings({ requireDeviceAuthOnAppOpen: false });
    expect(deviceAuthDecision('appOpen', { settings: off, osCredential: true })).toEqual({ required: false, lockless: false });
    expect(deviceAuthDecision('autofill', { settings: off, osCredential: true })).toEqual({ required: true, lockless: false });
  });

  it('follows Google Password Manager on a lockless device for open and fill, with the warning', () => {
    const bothOn = settings();
    expect(deviceAuthDecision('appOpen', { settings: bothOn, osCredential: false })).toEqual({ required: false, lockless: true });
    expect(deviceAuthDecision('autofill', { settings: bothOn, osCredential: false })).toEqual({ required: false, lockless: true });
  });

  it('always gates reveal, copy and export, even on a lockless device', () => {
    expect(deviceAuthDecision('revealCopy', { settings: settings({ requireDeviceAuthOnRevealCopy: false }), osCredential: true })).toEqual({ required: true, lockless: false });
    expect(deviceAuthDecision('revealCopy', { settings: settings(), osCredential: false })).toEqual({ required: true, lockless: true });
  });

  it('never makes the web vault gateless, even with no OS credential', () => {
    expect(deviceAuthDecision('appOpen', { settings: settings(), osCredential: false, webVault: true })).toEqual({ required: true, lockless: false });
  });
});

it('maps each gate to its own setting', () => {
  expect(deviceAuthSettingKey('appOpen')).toBe('requireDeviceAuthOnAppOpen');
  expect(deviceAuthSettingKey('autofill')).toBe('requireDeviceAuthOnAutofill');
  expect(deviceAuthSettingKey('revealCopy')).toBe('requireDeviceAuthOnRevealCopy');
});
