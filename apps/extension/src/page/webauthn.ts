// Converts between the page's WebAuthn objects and the JSON forms the core speaks (WebAuthn Level 3
// `toJSON` shapes, base64url binary). Runs in the page's world, so it only uses what it captured at
// start-up and never trusts the page with anything but its own request.

const toBytes = (source: BufferSource): Uint8Array => (ArrayBuffer.isView(source) ? new Uint8Array(source.buffer, source.byteOffset, source.byteLength) : new Uint8Array(source));

export function b64url(source: BufferSource): string {
  let binary = '';
  for (const byte of toBytes(source)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function fromB64url(text: string): ArrayBuffer {
  const binary = atob(text.replace(/-/g, '+').replace(/_/g, '/'));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

const descriptor = (d: PublicKeyCredentialDescriptor) => ({ type: d.type, id: b64url(d.id), ...(d.transports ? { transports: [...d.transports] } : {}) });

/**
 * PRF requests (the Octa Pass web vault's own device unlock among them) go straight to the
 * browser. The core's passkeys answer PRF (plan 05), but this in-page path doesn't pass it yet,
 * and the vault's own unlock passkey mustn't live in the vault the extension is unlocking.
 */
export function wantsPrf(options: { extensions?: AuthenticationExtensionsClientInputs } | undefined): boolean {
  return Boolean((options?.extensions as { prf?: unknown } | undefined)?.prf);
}

/** Extensions the core understands; others are dropped, as an authenticator that doesn't know them would. */
function extensions(inputs: AuthenticationExtensionsClientInputs | undefined) {
  return inputs?.credProps ? { extensions: { credProps: true } } : {};
}

export function creationOptionsToJSON(options: PublicKeyCredentialCreationOptions) {
  return {
    rp: { ...(options.rp.id ? { id: options.rp.id } : {}), name: options.rp.name },
    user: { id: b64url(options.user.id), name: options.user.name, displayName: options.user.displayName },
    challenge: b64url(options.challenge),
    pubKeyCredParams: options.pubKeyCredParams.map((p) => ({ type: p.type, alg: p.alg })),
    ...(options.timeout !== undefined ? { timeout: options.timeout } : {}),
    ...(options.excludeCredentials ? { excludeCredentials: options.excludeCredentials.map(descriptor) } : {}),
    ...(options.authenticatorSelection ? { authenticatorSelection: { ...options.authenticatorSelection } } : {}),
    ...(options.attestation ? { attestation: options.attestation } : {}),
    ...extensions(options.extensions),
  };
}

export function requestOptionsToJSON(options: PublicKeyCredentialRequestOptions) {
  return {
    challenge: b64url(options.challenge),
    ...(options.timeout !== undefined ? { timeout: options.timeout } : {}),
    ...(options.rpId ? { rpId: options.rpId } : {}),
    ...(options.allowCredentials ? { allowCredentials: options.allowCredentials.map(descriptor) } : {}),
    ...(options.userVerification ? { userVerification: options.userVerification } : {}),
  };
}

interface RegistrationJSON {
  id: string;
  rawId: string;
  type: 'public-key';
  authenticatorAttachment: string;
  clientExtensionResults: Record<string, unknown>;
  response: { clientDataJSON: string; attestationObject: string; authenticatorData: string; transports: string[]; publicKey: string; publicKeyAlgorithm: number };
}

interface AuthenticationJSON {
  id: string;
  rawId: string;
  type: 'public-key';
  authenticatorAttachment: string;
  clientExtensionResults: Record<string, unknown>;
  response: { clientDataJSON: string; authenticatorData: string; signature: string; userHandle?: string };
}

/**
 * A `PublicKeyCredential` the page can't tell apart: it has the right prototype (so `instanceof`
 * works) and own properties, which shadow the native getters that would throw on a plain object.
 */
function credential(json: RegistrationJSON | AuthenticationJSON, response: object): PublicKeyCredential {
  const proto = typeof PublicKeyCredential !== 'undefined' ? PublicKeyCredential.prototype : Object.prototype;
  const value = (v: unknown) => ({ value: v, enumerable: true });
  return Object.create(proto, {
    id: value(json.id),
    rawId: value(fromB64url(json.rawId)),
    type: value(json.type),
    authenticatorAttachment: value(json.authenticatorAttachment),
    response: value(response),
    getClientExtensionResults: { value: () => ({ ...json.clientExtensionResults }) },
    toJSON: { value: () => structuredClone(json) },
  }) as PublicKeyCredential;
}

function responseObject(proto: object | undefined, fields: Record<string, unknown>, methods: Record<string, () => unknown>): object {
  const descriptors: PropertyDescriptorMap = {};
  for (const [key, v] of Object.entries(fields)) descriptors[key] = { value: v, enumerable: true };
  for (const [key, fn] of Object.entries(methods)) descriptors[key] = { value: fn };
  return Object.create(proto ?? Object.prototype, descriptors);
}

export function registrationFromJSON(json: RegistrationJSON): PublicKeyCredential {
  const r = json.response;
  const response = responseObject(
    typeof AuthenticatorAttestationResponse !== 'undefined' ? AuthenticatorAttestationResponse.prototype : undefined,
    { clientDataJSON: fromB64url(r.clientDataJSON), attestationObject: fromB64url(r.attestationObject) },
    {
      getTransports: () => [...r.transports],
      getAuthenticatorData: () => fromB64url(r.authenticatorData),
      getPublicKey: () => fromB64url(r.publicKey),
      getPublicKeyAlgorithm: () => r.publicKeyAlgorithm,
    },
  );
  return credential(json, response);
}

export function assertionFromJSON(json: AuthenticationJSON): PublicKeyCredential {
  const r = json.response;
  const response = responseObject(
    typeof AuthenticatorAssertionResponse !== 'undefined' ? AuthenticatorAssertionResponse.prototype : undefined,
    {
      clientDataJSON: fromB64url(r.clientDataJSON),
      authenticatorData: fromB64url(r.authenticatorData),
      signature: fromB64url(r.signature),
      userHandle: r.userHandle ? fromB64url(r.userHandle) : null,
    },
    {},
  );
  return credential(json, response);
}
