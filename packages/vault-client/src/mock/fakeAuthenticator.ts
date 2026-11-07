// A software platform authenticator for tests: credentials.create/get with a real PRF (HMAC-SHA-256
// over the eval input with a per-credential secret), like the hmac-secret extension underneath.

export interface FakeAuthenticator {
  create: ReturnType<typeof vi.fn>;
  get: ReturnType<typeof vi.fn>;
  /** Make the next get fail as if the user dismissed the prompt. */
  cancelNext(): void;
  /** Make the next `call` fail with this error. */
  failNext(error: unknown, call?: 'create' | 'get'): void;
}

interface FakeOptions {
  prf?: boolean;
  available?: boolean;
  /** Return the PRF output from create when asked for one, as Safari and Firefox do. */
  prfAtCreate?: boolean;
}

const key = (bytes: ArrayBuffer | ArrayBufferView) => Array.from(ArrayBuffer.isView(bytes) ? new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength) : new Uint8Array(bytes)).join(',');

export function installFakeAuthenticator({ prf = true, available = true, prfAtCreate = false }: FakeOptions = {}): FakeAuthenticator {
  const secrets = new Map<string, Uint8Array<ArrayBuffer>>();
  const failures: { create?: unknown; get?: unknown } = {};
  const failIfAsked = (call: 'create' | 'get') => {
    const error = failures[call];
    if (error === undefined) return;
    delete failures[call];
    throw error;
  };

  const evaluate = async (secret: Uint8Array<ArrayBuffer>, extensions: AuthenticationExtensionsClientInputs | undefined) => {
    const input = (extensions as { prf?: { eval?: { first: BufferSource } } } | undefined)?.prf?.eval?.first;
    if (!input) return undefined;
    const hmac = await crypto.subtle.importKey('raw', secret, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    return crypto.subtle.sign('HMAC', hmac, input);
  };

  const create = vi.fn(async (options: CredentialCreationOptions) => {
    failIfAsked('create');
    const id = crypto.getRandomValues(new Uint8Array(16));
    const secret = crypto.getRandomValues(new Uint8Array(32));
    secrets.set(key(id), secret);
    const first = prf && prfAtCreate ? await evaluate(secret, options.publicKey!.extensions) : undefined;
    return { rawId: id.buffer, getClientExtensionResults: () => ({ prf: { enabled: prf, ...(first ? { results: { first } } : {}) } }) };
  });

  const get = vi.fn(async (options: CredentialRequestOptions) => {
    failIfAsked('get');
    const publicKey = options.publicKey!;
    const secret = secrets.get(key(publicKey.allowCredentials![0]!.id as ArrayBufferView));
    if (!secret) throw new DOMException('No credential', 'NotAllowedError');
    const first = await evaluate(secret, publicKey.extensions);
    return { getClientExtensionResults: () => (prf && first ? { prf: { results: { first } } } : {}) };
  });

  Object.defineProperty(navigator, 'credentials', { configurable: true, value: { create, get } });
  vi.stubGlobal('PublicKeyCredential', { isUserVerifyingPlatformAuthenticatorAvailable: async () => available });
  return {
    create,
    get,
    cancelNext: () => (failures.get = new DOMException('The operation either timed out or was not allowed.', 'NotAllowedError')),
    failNext: (error, call = 'get') => (failures[call] = error),
  };
}
