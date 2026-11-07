/** Stable error codes. The UI maps each one to a message that says what to do next. */
export type VaultErrorCode =
  /** A developer toolkit tool refused its input; the message holds the core's error code. */
  | 'toolFailed'
  | 'invalidCredentials'
  /** The identity provider hasn't finished in the browser yet. */
  | 'ssoPending'
  /** The identity provider's settings don't work. */
  | 'ssoConfig'
  /** An organisation policy forbids this. */
  | 'orgPolicy'
  /** This would leave organisation vaults with nobody able to manage them. */
  | 'orgVaultOrphaned'
  | 'secretKeyRequired'
  | 'invalidSecretKey'
  | 'emailTaken'
  | 'invalidEmail'
  | 'invalidVerificationCode'
  | 'signupExpired'
  /** A master password reset that took too long or was already used: start over. */
  | 'resetExpired'
  /** The recovery code doesn't open this account (an old Recovery Kit, or another account's). */
  | 'invalidRecoveryCode'
  | 'signupsClosed'
  | 'insecureServerUrl'
  | 'serverUnreachable'
  | 'serverError'
  | 'rateLimited'
  | 'sessionExpired'
  | 'accountDeleted'
  | 'reauthRequired'
  | 'locked'
  | 'notFound'
  | 'readOnlyVault'
  | 'invalidImportFile'
  /** The import file is password-protected: ask for its password and try again. */
  | 'importPasswordRequired'
  | 'wrongImportPassword'
  /** The file isn't a PNG, JPEG, WebP or GIF image (reading QR codes). */
  | 'invalidImage'
  /** An import review that was already finished, cancelled, or forgotten when the vault locked. */
  | 'importReviewExpired'
  /** The desktop app may not read the screen: the user turns on Screen Recording for it in System Settings. */
  | 'screenCaptureDenied'
  | 'emailMismatch'
  | 'deviceUnlockUnsupported'
  /** The device prompt didn't finish: dismissed, timed out, or refused. The message carries the browser's reason. */
  | 'deviceUnlockCancelled'
  | 'deviceUnlockFailed'
  /** The passkey is made, but this browser needs one more click to read its key: ask, then call enable again. */
  | 'deviceUnlockConfirm'
  /** Turning device unlock on failed for a reason other than the prompt; the message carries the browser's reason. */
  | 'deviceUnlockSetupFailed'
  | 'passwordRequired'
  | 'accountNotFound'
  | 'notAllowed'
  | 'alreadyExists'
  | 'familyFull'
  | 'quotaExceeded'
  | 'untrustedVault'
  /** The key log doesn't back up the keys the server offered for someone: nothing was sealed to them. */
  | 'keyLogMismatch'
  | 'wrongPassphrase'
  /** The SSH key file is protected by a passphrase: ask for it and try again. */
  | 'sshPassphraseRequired'
  /** Not an SSH private key, or a damaged one. */
  | 'invalidSshKey'
  /** A key file format or cipher Octa Pass can't read (PuTTY, 3DES-encrypted PEM, …), or a key it can't convert. */
  | 'unsupportedSshKey'
  /** A public key (`.pub`) was given where the private key was needed. */
  | 'sshPublicKeyOnly'
  | 'invalidShareLink'
  | 'fileTooLarge'
  /** A vault on this device only has no account: this needs Turn on sync. */
  | 'needsSync'
  /** A local vault's master password is too easy to guess (plan 03). */
  | 'weakMasterPassword'
  /** A backup file that's damaged, isn't one, or doesn't open with that password or code. */
  | 'invalidBackup'
  /** A local vault needs a name. */
  | 'invalidName'
  /** A wrong or already used two-step code, or a security key the server didn't accept. Try again. */
  | 'invalidTwoStepCode'
  /** The two-step sign-in waited too long or had too many wrong tries: sign in again from the start. */
  | 'twoStepExpired'
  /** The security key prompt was dismissed or timed out. */
  | 'securityKeyCancelled'
  /** This app or browser can't use the account's security keys (another site's keys, or no WebAuthn). */
  | 'securityKeyUnsupported'
  /** No masked email provider is connected (or none can be used here). */
  | 'maskedEmailNotSetUp'
  /** The browser blocks calls to this provider from web pages (no CORS): use the extension or the apps. */
  | 'maskedEmailBlocked'
  /** The provider turned the API token down. */
  | 'maskedEmailToken'
  | 'maskedEmailRateLimited'
  | 'maskedEmailUnreachable'
  /** The provider answered with an error; the message carries its words when it gave any. */
  | 'maskedEmailFailed'
  /** The phone apps: no app on the phone opens this kind of file. */
  | 'noFileViewer'
  /** The phone apps: there's no camera, or Octa Pass isn't allowed to use it. */
  | 'cameraUnavailable';

export class VaultError extends Error {
  readonly code: VaultErrorCode;

  constructor(code: VaultErrorCode, message: string = code) {
    super(message);
    this.name = 'VaultError';
    this.code = code;
  }
}

export function isVaultError(error: unknown, code?: VaultErrorCode): error is VaultError {
  return error instanceof VaultError && (code === undefined || error.code === code);
}
