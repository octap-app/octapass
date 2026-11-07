// The MAIN-world script: wraps navigator.credentials.create/get so Octa Pass can answer passkey
// requests (plan 05, Passkeys). Each call goes to the content script over a fresh MessagePort; the
// user then picks Octa Pass or the browser's own flow in the Octa Pass prompt.

import { assertionFromJSON, creationOptionsToJSON, registrationFromJSON, requestOptionsToJSON, wantsPrf } from './webauthn';
import { PAGE_SOURCE, type PageReply, type PageRequest } from './bridge';

const credentials = navigator.credentials as CredentialsContainer | undefined;

if (credentials && typeof PublicKeyCredential !== 'undefined') {
  const originalCreate = credentials.create.bind(credentials);
  const originalGet = credentials.get.bind(credentials);
  const post = window.postMessage.bind(window);

  const ask = (request: PageRequest, signal: AbortSignal | undefined): Promise<PageReply> =>
    new Promise((resolve, reject) => {
      if (signal?.aborted) return reject(signal.reason ?? new DOMException('The operation was aborted.', 'AbortError'));
      const channel = new MessageChannel();
      channel.port1.onmessage = (event: MessageEvent<PageReply>) => {
        channel.port1.close();
        resolve(event.data);
      };
      signal?.addEventListener('abort', () => {
        channel.port1.postMessage({ cancel: true });
        channel.port1.close();
        reject(signal.reason ?? new DOMException('The operation was aborted.', 'AbortError'));
      });
      post({ source: PAGE_SOURCE, request }, '*', [channel.port2]);
    });

  const failure = (reply: Extract<PageReply, { kind: 'error' }>) => (reply.name === 'TypeError' ? new TypeError(reply.message) : new DOMException(reply.message, reply.name));

  const create = async function create(options?: CredentialCreationOptions): Promise<Credential | null> {
    // Straight through, with no round trip first: Safari only shows its prompt inside the click.
    if (!options?.publicKey || wantsPrf(options.publicKey)) return originalCreate(options);
    const reply = await ask({ kind: 'create', options: creationOptionsToJSON(options.publicKey) }, options.signal);
    if (reply.kind === 'fallback') return originalCreate(options);
    if (reply.kind === 'error') throw failure(reply);
    return registrationFromJSON(reply.credential as Parameters<typeof registrationFromJSON>[0]);
  };

  const get = async function get(options?: CredentialRequestOptions): Promise<Credential | null> {
    // Conditional requests feed the browser's own autofill UI; Octa Pass's inline menu doesn't list passkeys yet.
    if (!options?.publicKey || options.mediation === 'conditional' || wantsPrf(options.publicKey)) return originalGet(options);
    const reply = await ask({ kind: 'get', options: requestOptionsToJSON(options.publicKey) }, options.signal);
    if (reply.kind === 'fallback') return originalGet(options);
    if (reply.kind === 'error') throw failure(reply);
    return assertionFromJSON(reply.credential as Parameters<typeof assertionFromJSON>[0]);
  };

  // Look native to pages that check `toString()`.
  for (const [fn, original] of [[create, credentials.create], [get, credentials.get]] as const) {
    Object.defineProperty(fn, 'toString', { value: () => Function.prototype.toString.call(original) });
  }
  Object.defineProperty(credentials, 'create', { value: create, configurable: true, writable: true });
  Object.defineProperty(credentials, 'get', { value: get, configurable: true, writable: true });
}
