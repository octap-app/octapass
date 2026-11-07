import { assertionFromJSON, b64url, creationOptionsToJSON, fromB64url, registrationFromJSON, requestOptionsToJSON, wantsPrf } from './webauthn';

const bytes = (...values: number[]) => new Uint8Array(values);

describe('WebAuthn JSON conversion', () => {
  it('turns the page’s options into the JSON the core takes', () => {
    const json = creationOptionsToJSON({
      rp: { id: 'example.com', name: 'Example' },
      user: { id: bytes(1, 2, 3), name: 'maya', displayName: 'Maya' },
      challenge: bytes(255, 254).buffer,
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      excludeCredentials: [{ type: 'public-key', id: bytes(9) }],
      authenticatorSelection: { residentKey: 'required' },
      extensions: { credProps: true, prf: {} } as AuthenticationExtensionsClientInputs,
    });
    expect(json).toEqual({
      rp: { id: 'example.com', name: 'Example' },
      user: { id: 'AQID', name: 'maya', displayName: 'Maya' },
      challenge: '__4',
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      excludeCredentials: [{ type: 'public-key', id: 'CQ' }],
      authenticatorSelection: { residentKey: 'required' },
      extensions: { credProps: true },
    });
    expect(requestOptionsToJSON({ challenge: bytes(1), allowCredentials: [{ type: 'public-key', id: bytes(2), transports: ['internal'] }] })).toEqual({
      challenge: 'AQ',
      allowCredentials: [{ type: 'public-key', id: 'Ag', transports: ['internal'] }],
    });
  });

  it('round-trips base64url', () => {
    const data = crypto.getRandomValues(new Uint8Array(33));
    expect(new Uint8Array(fromB64url(b64url(data)))).toEqual(data);
  });

  it('builds credentials with ArrayBuffers and the response methods pages use', () => {
    const registration = registrationFromJSON({
      id: 'AQ',
      rawId: 'AQ',
      type: 'public-key',
      authenticatorAttachment: 'platform',
      clientExtensionResults: { credProps: { rk: true } },
      response: { clientDataJSON: 'e30', attestationObject: 'oA', authenticatorData: 'AA', transports: ['internal', 'hybrid'], publicKey: 'MA', publicKeyAlgorithm: -7 },
    });
    expect(registration.id).toBe('AQ');
    expect(new Uint8Array(registration.rawId)).toEqual(bytes(1));
    const response = registration.response as AuthenticatorAttestationResponse;
    expect(new TextDecoder().decode(response.clientDataJSON)).toBe('{}');
    expect(response.getTransports()).toEqual(['internal', 'hybrid']);
    expect(response.getPublicKeyAlgorithm()).toBe(-7);
    expect(registration.getClientExtensionResults()).toEqual({ credProps: { rk: true } });

    const assertion = assertionFromJSON({
      id: 'Ag',
      rawId: 'Ag',
      type: 'public-key',
      authenticatorAttachment: 'platform',
      clientExtensionResults: {},
      response: { clientDataJSON: 'e30', authenticatorData: 'AA', signature: 'MEU', userHandle: 'dQ' },
    });
    expect(new Uint8Array((assertion.response as AuthenticatorAssertionResponse).userHandle!)).toEqual(bytes(117));
    expect((assertion.toJSON() as { id: string }).id).toBe('Ag');
  });
});

describe('requests the browser answers', () => {
  it('leaves PRF requests to the device’s own authenticator', () => {
    expect(wantsPrf({ extensions: { prf: { eval: { first: bytes(1) } } } as AuthenticationExtensionsClientInputs })).toBe(true);
    expect(wantsPrf({ extensions: { prf: {} } as AuthenticationExtensionsClientInputs })).toBe(true);
    expect(wantsPrf({ extensions: { credProps: true } })).toBe(false);
    expect(wantsPrf({})).toBe(false);
    expect(wantsPrf(undefined)).toBe(false);
  });
});
