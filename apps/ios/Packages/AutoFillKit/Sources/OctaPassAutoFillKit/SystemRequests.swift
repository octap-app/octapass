import AuthenticationServices
import CryptoKit
import OctaPassCore

/// The system's AutoFill requests in the core's terms.
public enum SystemRequests {
    /// What to match logins against: each website the system names, once, as an `http`/`https`
    /// address. Safari usually names the page as a `.domain`; other browsers (Chrome) and apps
    /// may send the page's full `.URL`, a domain with a scheme, a bare host as a `.URL`, an empty
    /// identifier, a page that isn't a website (`about:blank`) or, from iOS 26.2, the browser's
    /// own App ID (`.app`). Only the websites are kept, so the rest can't hide them.
    public static func urls(for identifiers: [ASCredentialServiceIdentifier]) -> [String] {
        var seen = Set<String>()
        return identifiers.compactMap(website).filter { seen.insert($0).inserted }
    }

    /// The website a service identifier names, or nil when it names none.
    public static func website(_ identifier: ASCredentialServiceIdentifier) -> String? {
        let text = identifier.identifier.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return nil }
        switch identifier.type {
        case .domain, .URL: return website(text)
        // An App ID (`.app`, iOS 26.2) or a type this SDK doesn't know: only a full web address.
        default: return scheme(of: text).flatMap { ["http", "https"].contains($0) ? text : nil }
        }
    }

    /// `https://github.com/login` as it is, `github.com` or `github.com/login` as `https://…`;
    /// nil for another scheme (`about:`, `chrome://`, `androidapp://` …).
    public static func website(_ text: String) -> String? {
        let text = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return nil }
        guard let scheme = scheme(of: text) else { return "https://" + text }
        return ["http", "https"].contains(scheme) ? text : nil
    }

    /// The lower-case scheme of `scheme:…`; nil for none, and for `localhost:8080`, a host and port.
    static func scheme(of text: String) -> String? {
        guard let colon = text.firstIndex(of: ":") else { return nil }
        let name = text[..<colon]
        guard let first = name.first, first.isASCII, first.isLetter,
              name.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || "+-.".contains($0)) })
        else { return nil }
        let rest = text[text.index(after: colon)...]
        if !rest.hasPrefix("//"), rest.first?.isNumber == true { return nil }
        return name.lowercased()
    }

    /// The passkey to create, from `ASPasskeyCredentialRequest`.
    public static func creation(
        identity: ASPasskeyCredentialIdentity,
        algorithms: [ASCOSEAlgorithmIdentifier],
        excluded: [Data],
        prf: PasskeyPrfRequest? = nil
    ) -> PasskeyCreationRequest {
        PasskeyCreationRequest(
            rpId: identity.relyingPartyIdentifier,
            rpName: identity.relyingPartyIdentifier,
            userHandle: identity.userHandle,
            userName: identity.userName,
            userDisplayName: identity.userName,
            algorithms: algorithms.map { Int64($0.rawValue) },
            excludedCredentials: excluded,
            challenge: Data(),
            credProps: false,
            prf: prf)
    }

    public static func registration(_ registration: PasskeyRegistration, rpId: String, clientDataHash: Data) -> ASPasskeyRegistrationCredential {
        let credential = ASPasskeyRegistrationCredential(
            relyingParty: rpId,
            clientDataHash: clientDataHash,
            credentialID: registration.credentialId,
            attestationObject: registration.attestationObject)
        if #available(iOS 18.0, macOS 15.0, *), let prf = registration.prf {
            credential.extensionOutput = ASPasskeyRegistrationCredentialExtensionOutput(prf: registrationOutput(prf))
        }
        return credential
    }

    public static func assertion(_ assertion: PasskeyAssertion, rpId: String, clientDataHash: Data) -> ASPasskeyAssertionCredential {
        let credential = ASPasskeyAssertionCredential(
            userHandle: assertion.userHandle,
            relyingParty: rpId,
            signature: assertion.signature,
            clientDataHash: clientDataHash,
            authenticatorData: assertion.authenticatorData,
            credentialID: assertion.credentialId)
        if #available(iOS 18.0, macOS 15.0, *), let first = assertion.prf?.first {
            credential.extensionOutput = ASPasskeyAssertionCredentialExtensionOutput(
                prf: ASAuthorizationPublicKeyCredentialPRFAssertionOutput(
                    first: SymmetricKey(data: first), second: assertion.prf?.second.map { SymmetricKey(data: $0) }))
        }
        return credential
    }

    // MARK: PRF (plan 05, *PRF on Octa Pass's own passkeys*)

    /// A registration's PRF request: `inputValues`, or none when the site only checks for support.
    /// The salts are the page's inputs; the core hashes them with "WebAuthn PRF".
    @available(iOS 18.0, macOS 15.0, *)
    public static func prf(_ input: ASAuthorizationPublicKeyCredentialPRFRegistrationInput?) -> PasskeyPrfRequest? {
        guard let input else { return nil }
        return PasskeyPrfRequest(eval: input.inputValues.map(prfInput), byCredential: [])
    }

    /// A sign-in's PRF request: `inputValues` for any passkey, `perCredentialInputValues` by ID.
    @available(iOS 18.0, macOS 15.0, *)
    public static func prf(_ input: ASAuthorizationPublicKeyCredentialPRFAssertionInput?) -> PasskeyPrfRequest? {
        guard let input else { return nil }
        return PasskeyPrfRequest(
            eval: input.inputValues.map(prfInput),
            byCredential: (input.perCredentialInputValues ?? [:]).map {
                PasskeyPrfCredentialInput(credentialId: $0.key, input: prfInput($0.value))
            })
    }

    @available(iOS 18.0, macOS 15.0, *)
    static func prfInput(_ values: ASAuthorizationPublicKeyCredentialPRFAssertionInput.InputValues) -> PasskeyPrfInput {
        PasskeyPrfInput(first: values.saltInput1, second: values.saltInput2)
    }

    @available(iOS 18.0, macOS 15.0, *)
    static func registrationOutput(_ prf: PasskeyPrfOutput) -> ASAuthorizationPublicKeyCredentialPRFRegistrationOutput {
        guard let first = prf.first else { return prf.enabled ? .supported : .unsupported }
        return ASAuthorizationPublicKeyCredentialPRFRegistrationOutput(
            first: SymmetricKey(data: first), second: prf.second.map { SymmetricKey(data: $0) })
    }
}
