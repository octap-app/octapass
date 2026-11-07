import type { IconName } from '@octapass/ui';
import type { DevicePlatform, UnlockMethods } from '@octapass/vault-client';
import { t, type MessageKey } from '../i18n';

// "other" would read as a plural form in the catalog, so it's stored as "generic".
const catalogKey = (platform: DevicePlatform) => (platform === 'other' ? 'generic' : platform);

/** What people call their device's lock here: "Touch ID" on a Mac, "Windows Hello" on Windows… */
export function deviceMethodName(platform: DevicePlatform): string {
  return t(`unlock.method.${catalogKey(platform)}` as MessageKey);
}

export function deviceMethodHelp(platform: DevicePlatform): string {
  return t(`unlock.help.${catalogKey(platform)}` as MessageKey);
}

export function deviceIcon(platform: DevicePlatform): IconName {
  return platform === 'ios' ? 'faceId' : 'fingerprint';
}

/**
 * What the offer after sign-in calls the device's lock: the system's own name where it has one
 * (Face ID, Touch ID, Windows Hello), else a phrase for the platform.
 */
export function offerMethodName({ platform, label }: Pick<UnlockMethods, 'platform' | 'label'>): string {
  if (['Face ID', 'Touch ID', 'Optic ID', 'Windows Hello'].includes(label)) return label;
  if (platform === 'ios') return t('unlockOffer.passcode');
  if (platform === 'mac') return t('unlockOffer.macPassword');
  if (platform === 'android') return t('unlockOffer.android');
  return t('unlockOffer.device');
}
