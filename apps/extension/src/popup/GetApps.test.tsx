import { missingApps } from './GetApps';

describe('the offer of the other apps', () => {
  const none = { desktopHere: false, safari: false, local: false };

  it('offers the desktop app, then the phone app, when the account has neither', () => {
    expect(missingApps({ ...none, devices: [{ platform: 'extension' }, { platform: 'web' }] })).toEqual(['desktop', 'mobile']);
  });

  it('knows the desktop app from native messaging or from another computer signed in', () => {
    expect(missingApps({ ...none, desktopHere: true, devices: [] })).toEqual(['mobile']);
    expect(missingApps({ ...none, devices: [{ platform: 'mac' }] })).toEqual(['mobile']);
    expect(missingApps({ ...none, devices: [{ platform: 'windows' }, { platform: 'android' }] })).toEqual([]);
  });

  it('never offers the Mac app in Safari, which comes inside it', () => {
    expect(missingApps({ ...none, safari: true, devices: [{ platform: 'ios' }] })).toEqual([]);
  });

  it('offers no phone app without the device list, or for a vault on this device only', () => {
    expect(missingApps({ ...none, devices: undefined })).toEqual(['desktop']);
    expect(missingApps({ ...none, local: true, devices: undefined })).toEqual(['desktop']);
  });
});
