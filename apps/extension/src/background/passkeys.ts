// Answers websites' passkey requests with the core authenticator (plan 13, I), after the user chose
// Octa Pass in the prompt. The core works on encrypted items, so private keys stay in WASM.
//
// The engine doesn't expose its session, so each request opens its own (accountSession.ts).

import type {
  AuthenticationResponseJSON,
  PasskeyCaller,
  PasskeyCandidate,
  PasskeyMatch,
  PasskeyTarget,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from '@octapass/core';
import { normalizeEmail, VaultError, type ItemDraft, type ItemSummary, type LoginDetails } from '@octapass/vault-client';
import type { Core } from '@octapass/vault-client/remote';
import { withAccountSession, type AccountCache as Cache, type AccountSession, type AccountSessionOptions } from './accountSession';
import type { Matcher } from './matching';
import type { VaultHost } from './vault';

/** What the page gets back: a DOMException (or TypeError) name and a message. */
export class PasskeyError extends Error {
  constructor(
    readonly domName: string,
    message: string,
  ) {
    super(message);
    this.name = 'PasskeyError';
  }
}

const CORE_ERRORS: Record<string, string> = {
  passkey_rp_mismatch: 'SecurityError',
  passkey_frame_not_allowed: 'NotAllowedError',
  passkey_excluded: 'InvalidStateError',
  passkey_unsupported_algorithm: 'NotSupportedError',
  passkey_not_found: 'NotAllowedError',
  invalid_passkey_request: 'TypeError',
};

/** Maps a core error to what `navigator.credentials` would throw (`crates/octapass-wasm/README.md`). */
export function toPasskeyError(error: unknown): PasskeyError {
  if (error instanceof PasskeyError) return error;
  const code = (error as { code?: unknown }).code;
  if (typeof code === 'string' && CORE_ERRORS[code]) return new PasskeyError(CORE_ERRORS[code], code);
  if (error instanceof VaultError) return new PasskeyError('NotAllowedError', error.code);
  return new PasskeyError('NotAllowedError', 'The operation failed.');
}

export interface PasskeyAuthenticatorOptions extends AccountSessionOptions {
  host: VaultHost;
  matcher: Matcher;
}

export class PasskeyAuthenticator {
  constructor(private readonly options: PasskeyAuthenticatorOptions) {}

  /** Makes a passkey, saves it into the login for this account (or a new login) and returns the credential. */
  async create(options: PublicKeyCredentialCreationOptionsJSON, caller: PasskeyCaller): Promise<RegistrationResponseJSON> {
    return this.withSession(async ({ core, session, cache, summaries, untrusted }) => {
      const others = this.candidates(cache, summaries.filter((s) => s.hasPasskey));
      const target = (await this.loginFor(cache, untrusted, summaries, options, caller)) ?? (await this.newLogin(core, cache));
      const created = session.createPasskey(options, caller, target, others);
      const { overview, details } = session.decryptItem(target.vaultId, target.itemId, created.item);
      const record = cache.items.find((r) => r.id === target.itemId);
      const draft = (record ? { id: record.id, vaultId: record.vaultId, revision: record.revision, overview, details } : { vaultId: target.vaultId, overview, details }) as ItemDraft;
      await this.options.host.engine.call('saveItem', [draft]);
      return created.credential;
    });
  }

  /** The user's passkeys that can answer this request, for the prompt. */
  async find(options: PublicKeyCredentialRequestOptionsJSON, caller: PasskeyCaller): Promise<PasskeyMatch[]> {
    return this.withSession(async ({ session, cache, summaries }) => session.findPasskeys(options, caller, this.candidates(cache, summaries.filter((s) => s.hasPasskey))));
  }

  async assert(options: PublicKeyCredentialRequestOptionsJSON, caller: PasskeyCaller, match: Pick<PasskeyMatch, 'itemId' | 'credentialId'>): Promise<AuthenticationResponseJSON> {
    return this.withSession(async ({ session, cache, summaries }) => {
      const [candidate] = this.candidates(cache, summaries.filter((s) => s.id === match.itemId && s.hasPasskey));
      if (!candidate) throw new PasskeyError('NotAllowedError', 'passkey_not_found');
      return session.getAssertion(options, caller, candidate, match.credentialId);
    });
  }

  private async withSession<T>(fn: (context: AccountSession & { summaries: ItemSummary[] }) => Promise<T>): Promise<T> {
    const { host } = this.options;
    // Passkeys need an account: a vault on this device only answers with the browser's own flow.
    if (!host.unlocked || host.local) throw new PasskeyError('NotAllowedError', 'locked');
    try {
      const summaries = await host.listItems();
      return await withAccountSession(this.options, (context) => fn({ ...context, summaries }));
    } catch (error) {
      throw toPasskeyError(error);
    }
  }

  private candidates(cache: Cache, summaries: ItemSummary[]): PasskeyCandidate[] {
    const ids = new Set(summaries.map((s) => s.id));
    return cache.items
      .filter((r) => ids.has(r.id) && !r.deletedAt)
      .map((r) => ({ vaultId: r.vaultId, itemId: r.id, item: { encryptedItemKey: r.encryptedItemKey, overview: r.overview, details: r.details } }));
  }

  /** The login for this site and account name, so the passkey sits next to the password. */
  private async loginFor(cache: Cache, untrusted: Set<string>, summaries: ItemSummary[], options: PublicKeyCredentialCreationOptionsJSON, caller: PasskeyCaller): Promise<PasskeyTarget | undefined> {
    const writable = new Set(cache.vaults.filter((v) => v.role !== 'read' && !untrusted.has(v.id)).map((v) => v.id));
    const name = normalizeEmail(options.user.name);
    // Passkeys follow WebAuthn's rpId, not the page's part of the site: a login on another part counts too.
    const { matcher } = this.options;
    const logins = [...matcher.logins(summaries, caller.origin), ...matcher.otherLogins(summaries, caller.origin).map((o) => o.item)];
    for (const summary of logins) {
      if (summary.type !== 'login' || !writable.has(summary.vaultId)) continue;
      const item = await this.options.host.getItem(summary.id);
      const username = (item.details as LoginDetails).username;
      if (username && normalizeEmail(username) === name) return this.candidates(cache, [summary])[0];
    }
    return undefined;
  }

  private async newLogin(core: Core, cache: Cache): Promise<PasskeyTarget> {
    const personal = cache.vaults.find((v) => v.type === 'personal');
    if (!personal) throw new PasskeyError('NotAllowedError', 'notFound');
    return { vaultId: personal.id, itemId: core.newId() };
  }
}
