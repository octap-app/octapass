import { VaultError, type VaultErrorCode } from '../errors';
import { ApiProblem, toVaultError } from './http';

const CORE_ERRORS: Partial<Record<string, VaultErrorCode>> = {
  login_failed: 'invalidCredentials',
  invalid_secret_key: 'invalidSecretKey',
  device_unlock_failed: 'deviceUnlockFailed',
  // The server sent KDF parameters below the minimum: don't use it.
  unsupported_kdf: 'serverError',
  invalid_signature: 'untrustedVault',
  invalid_grant: 'untrustedVault',
  key_log_mismatch: 'keyLogMismatch',
  wrong_passphrase: 'wrongPassphrase',
  invalid_share_link: 'invalidShareLink',
};

function isCoreError(error: unknown): error is Error & { code: string } {
  return error instanceof Error && error.name === 'OctaPassError' && typeof (error as { code?: unknown }).code === 'string';
}

/** Turns server problems and crypto core errors into the `VaultError` codes the UI knows. */
export function normalizeError(error: unknown): unknown {
  if (error instanceof ApiProblem) return toVaultError(error);
  if (isCoreError(error)) {
    const code = CORE_ERRORS[error.code];
    return code ? new VaultError(code) : error;
  }
  return error;
}

/** On sharing calls a 403 means the role or relationship doesn't allow it, not that a vault is read-only. */
export async function asNotAllowed<T>(call: Promise<T>): Promise<T> {
  try {
    return await call;
  } catch (error) {
    if (error instanceof ApiProblem && error.status === 403 && error.type === 'forbidden') throw new VaultError('notAllowed');
    throw error;
  }
}
