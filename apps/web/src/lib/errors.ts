import { isVaultError, type VaultErrorCode } from '@octapass/vault-client';
import { t, type MessageKey } from '../i18n';

const messages: Record<VaultErrorCode, MessageKey> = {
  ssoPending: 'errors.ssoPending',
  ssoConfig: 'errors.ssoConfig',
  orgPolicy: 'errors.orgPolicy',
  orgVaultOrphaned: 'errors.orgVaultOrphaned',
  toolFailed: 'tools.errors.unknown',
  invalidCredentials: 'errors.invalidCredentials',
  secretKeyRequired: 'errors.secretKeyRequired',
  invalidSecretKey: 'errors.invalidSecretKey',
  emailTaken: 'errors.emailTaken',
  invalidEmail: 'errors.invalidEmail',
  invalidVerificationCode: 'errors.invalidVerificationCode',
  signupExpired: 'errors.signupExpired',
  resetExpired: 'errors.resetExpired',
  invalidRecoveryCode: 'errors.invalidRecoveryCode',
  signupsClosed: 'errors.signupsClosed',
  insecureServerUrl: 'errors.insecureServerUrl',
  serverUnreachable: 'errors.serverUnreachable',
  serverError: 'errors.serverError',
  rateLimited: 'errors.rateLimited',
  sessionExpired: 'errors.sessionExpired',
  accountDeleted: 'errors.accountDeleted',
  reauthRequired: 'errors.reauthRequired',
  locked: 'errors.locked',
  notFound: 'errors.notFound',
  readOnlyVault: 'errors.readOnlyVault',
  invalidImportFile: 'errors.invalidImportFile',
  importPasswordRequired: 'errors.importPasswordRequired',
  wrongImportPassword: 'errors.wrongImportPassword',
  invalidImage: 'errors.invalidImage',
  importReviewExpired: 'errors.importReviewExpired',
  screenCaptureDenied: 'errors.screenCaptureDenied',
  emailMismatch: 'errors.emailMismatch',
  deviceUnlockUnsupported: 'unlock.unsupported',
  deviceUnlockCancelled: 'errors.deviceUnlockCancelled',
  deviceUnlockFailed: 'errors.deviceUnlockFailed',
  deviceUnlockConfirm: 'unlock.confirmHelp',
  deviceUnlockSetupFailed: 'errors.deviceUnlockSetupFailed',
  passwordRequired: 'lock.passwordRequired',
  accountNotFound: 'errors.accountNotFound',
  notAllowed: 'errors.notAllowed',
  alreadyExists: 'errors.alreadyExists',
  familyFull: 'errors.familyFull',
  quotaExceeded: 'errors.quotaExceeded',
  untrustedVault: 'errors.untrustedVault',
  keyLogMismatch: 'errors.keyLogMismatch',
  wrongPassphrase: 'errors.wrongPassphrase',
  sshPassphraseRequired: 'errors.sshPassphraseRequired',
  invalidSshKey: 'errors.invalidSshKey',
  unsupportedSshKey: 'errors.unsupportedSshKey',
  sshPublicKeyOnly: 'errors.sshPublicKeyOnly',
  invalidShareLink: 'errors.invalidShareLink',
  fileTooLarge: 'errors.fileTooLarge',
  invalidTwoStepCode: 'errors.invalidTwoStepCode',
  twoStepExpired: 'errors.twoStepExpired',
  securityKeyCancelled: 'errors.securityKeyCancelled',
  securityKeyUnsupported: 'errors.securityKeyUnsupported',
  needsSync: 'errors.needsSync',
  weakMasterPassword: 'errors.weakMasterPassword',
  invalidBackup: 'errors.invalidBackup',
  invalidName: 'errors.invalidName',
  maskedEmailNotSetUp: 'errors.maskedEmailNotSetUp',
  maskedEmailBlocked: 'errors.maskedEmailBlocked',
  maskedEmailToken: 'errors.maskedEmailToken',
  maskedEmailRateLimited: 'errors.maskedEmailRateLimited',
  maskedEmailUnreachable: 'errors.maskedEmailUnreachable',
  maskedEmailFailed: 'errors.maskedEmailFailed',
  noFileViewer: 'errors.noFileViewer',
  cameraUnavailable: 'errors.cameraUnavailable',
};

const deviceCodes = new Set<VaultErrorCode>(['deviceUnlockCancelled', 'deviceUnlockFailed', 'deviceUnlockSetupFailed', 'deviceUnlockUnsupported']);

/** A sentence that says what went wrong and what to do next. */
export function errorMessage(error: unknown): string {
  if (isVaultError(error)) {
    // Import errors carry a specific reason from the parser, and provider errors the provider's words.
    if ((error.code === 'invalidImportFile' || error.code === 'maskedEmailFailed') && error.message !== error.code) return `${t(messages[error.code])} ${error.message}`;
    if (error.code === 'maskedEmailBlocked') return t(messages[error.code], { provider: error.message });
    // Device prompts carry the browser's own reason, which is often the only clue to what went wrong.
    if (deviceCodes.has(error.code) && error.message !== error.code) return `${t(messages[error.code])} ${t('errors.browserSaid', { reason: error.message })}`;
    return t(messages[error.code]);
  }
  if (error instanceof TypeError && /fetch|network/i.test(error.message)) return t('errors.offline');
  return t('errors.unexpected');
}
