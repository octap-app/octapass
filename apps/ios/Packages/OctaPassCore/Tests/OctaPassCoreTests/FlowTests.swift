import CryptoKit
import Foundation
import OctaPassCore
import XCTest

/// What the app does with URLSession, minus the network: every request goes to the in-process
/// TestServer, through the same native callback the app implements.
final class Loopback: HttpClient, @unchecked Sendable {
    let server: TestServer
    init(_ server: TestServer) { self.server = server }

    func send(request: HttpRequest) throws -> HttpResponse {
        server.handle(request: request)
    }
}

final class FlowTests: XCTestCase {
    let email = "alice@example.com"
    let password = "correct horse battery staple"
    var directory: URL!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try FileManager.default.removeItem(at: directory)
    }

    func signedIn(_ result: LogInResult) throws -> SignedIn {
        guard case let .signedIn(signedIn) = result else {
            XCTFail("expected no second step")
            throw OctaPassError.LoginFailed
        }
        return signedIn
    }

    func problemType(_ error: Error) -> String? {
        guard case let .Server(_, problemType, _) = error as? OctaPassError else { return nil }
        return problemType
    }

    func testSignUpLogInFillTotpAndPasskeys() throws {
        let server = TestServer()
        let api = try OctaPassServer(baseUrl: "https://octapass.test", http: Loopback(server))
        XCTAssertEqual(try api.serverInfo().apiVersion, 1)

        // Sign-up, then save a login on this device and upload it (encrypt).
        let signup = try api.startSignup(email: email, password: password)
        let secretKey = signup.secretKey()
        XCTAssertTrue(secretKey.hasPrefix("OP1-"))
        let device = DeviceInfo(name: "iPhone", platform: "ios")
        let laptop = try signup.finish(verificationCode: XCTUnwrap(signup.devVerificationCode()), device: device)
        let laptopStore = try LocalStore.create(
            path: directory.appending(path: "laptop.store").path, serverUrl: api.baseUrl(), session: laptop.session)
        try api.sync(accessToken: laptop.tokens.accessToken, store: laptopStore)
        let itemId = try laptop.session.saveLogin(store: laptopStore, draft: LoginDraft(
            itemId: nil, title: "GitHub", url: "https://github.com", username: "alice", password: "hunter2",
            totp: "JBSWY3DPEHPK3PXP"))
        try api.uploadPending(accessToken: laptop.tokens.accessToken, session: laptop.session, store: laptopStore)
        XCTAssertFalse(laptopStore.hasPendingChanges())
        XCTAssertEqual(server.itemCount(email: email), 1)

        // Log in on a new device with the Secret Key, then decrypt and fill.
        XCTAssertThrowsError(try api.logInTrusted(
            email: email, password: "wrong", secretKey: secretKey, device: device, trustedDeviceToken: nil)) {
            XCTAssertEqual($0 as? OctaPassError, .LoginFailed)
        }
        let phone = try signedIn(api.logInTrusted(
            email: email, password: password, secretKey: secretKey, device: device, trustedDeviceToken: nil))
        let storePath = directory.appending(path: "phone.store").path
        let store = try LocalStore.create(path: storePath, serverUrl: api.baseUrl(), session: phone.session)
        try api.sync(accessToken: phone.tokens.accessToken, store: store)
        let session = phone.session
        let matches = try session.matchLogins(store: store, url: "https://github.com/login")
        XCTAssertEqual(matches.map(\.item.itemId), [itemId])
        XCTAssertEqual(matches.first?.quality, .exact)
        XCTAssertTrue(try session.matchLogins(store: store, url: "https://github.com.evil.io").isEmpty)
        let item = try session.getItem(store: store, itemId: itemId)
        XCTAssertEqual(item.login?.password, "hunter2")

        let code = try session.totpCode(store: store, itemId: itemId)
        XCTAssertEqual(code.code.count, 6)
        XCTAssertEqual(code.period, 30)

        // A passkey the way ASPasskeyCredentialRequest asks for one: the system hashed clientDataJSON.
        let clientDataHash = Data(SHA256.hash(data: Data(#"{"type":"webauthn.create"}"#.utf8)))
        let created = try session.createPasskey(store: store, request: PasskeyCreationRequest(
            rpId: "example.com", rpName: "Example", userHandle: Data([1, 2, 3, 4]), userName: "alice",
            userDisplayName: "Alice", algorithms: [-7], excludedCredentials: [], challenge: Data(), credProps: false),
            client: .hash(clientDataHash: clientDataHash))
        let assertion = try session.getPasskeyAssertion(
            store: store,
            request: PasskeyAssertionRequest(rpId: "example.com", allowedCredentials: [], challenge: Data()),
            client: .hash(clientDataHash: clientDataHash),
            credentialId: created.credentialId)
        XCTAssertEqual(assertion.userHandle, Data([1, 2, 3, 4]))
        XCTAssertEqual(assertion.credentialId, created.credentialId)
        let response = try JSONSerialization.jsonObject(with: Data(created.responseJson.utf8)) as! [String: Any]
        let publicKey = try XCTUnwrap((response["response"] as? [String: Any])?["publicKey"] as? String)
        let key = try P256.Signing.PublicKey(derRepresentation: XCTUnwrap(base64url(publicKey)))
        let signature = try P256.Signing.ECDSASignature(derRepresentation: assertion.signature)
        XCTAssertTrue(key.isValidSignature(signature, for: assertion.authenticatorData + clientDataHash))

        let identities = try session.credentialIdentities(store: store)
        XCTAssertTrue(identities.contains { if case .passkey(_, "example.com", _, _, _) = $0 { true } else { false } })
    }

    func testTwoStepSignInAndTrustedDevices() throws {
        let server = TestServer()
        let api = try OctaPassServer(baseUrl: "https://octapass.test", http: Loopback(server))
        let signup = try api.startSignup(email: email, password: password)
        let secretKey = signup.secretKey()
        let device = DeviceInfo(name: "iPhone", platform: "ios")
        let laptop = try signup.finish(verificationCode: XCTUnwrap(signup.devVerificationCode()), device: device)
        let laptopTrust = try XCTUnwrap(laptop.tokens.trustedDeviceToken, "every sign-in trusts its device")
        server.enableTwoStep(email: email)

        // The old call can't finish it and says why.
        XCTAssertThrowsError(try api.logIn(email: email, password: password, secretKey: secretKey, device: device)) {
            XCTAssertEqual(self.problemType($0), "second-factor-required")
        }

        let result = try api.logInTrusted(
            email: email, password: password, secretKey: secretKey, device: device, trustedDeviceToken: nil)
        guard case let .secondFactorRequired(challenge) = result else { return XCTFail("expected a second step") }
        XCTAssertEqual(challenge.methods(), [.totp, .recoveryCode])
        XCTAssertThrowsError(try challenge.finishWithTotp(code: "000000")) {
            XCTAssertEqual(self.problemType($0), "invalid-second-factor")
        }
        let phone = try challenge.finishWithTotp(code: "654321")
        XCTAssertNotNil(phone.tokens.trustedDeviceToken)

        // A trusted device skips the second step.
        let again = try signedIn(api.logInTrusted(
            email: email, password: password, secretKey: secretKey, device: device, trustedDeviceToken: laptopTrust))
        XCTAssertNotEqual(again.tokens.trustedDeviceToken, laptopTrust, "the token is replaced")
    }

    func testTheAutoFillExtensionUnlocksWithTheDeviceLock() throws {
        let server = TestServer()
        let api = try OctaPassServer(baseUrl: "https://octapass.test", http: Loopback(server))
        let signup = try api.startSignup(email: email, password: password)
        let signedIn = try signup.finish(
            verificationCode: XCTUnwrap(signup.devVerificationCode()), device: DeviceInfo(name: "iPhone", platform: "ios"))
        let path = directory.appending(path: "shared.store").path
        let appStore = try LocalStore.create(path: path, serverUrl: api.baseUrl(), session: signedIn.session)
        try api.sync(accessToken: signedIn.tokens.accessToken, store: appStore)
        _ = try signedIn.session.saveLogin(store: appStore, draft: LoginDraft(
            itemId: nil, title: nil, url: "https://example.com", username: "alice", password: "pw", totp: nil))

        // The app turns device unlock on with a secret it keeps behind Face ID / the passcode.
        let deviceSecret = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        try appStore.enableDeviceUnlock(session: signedIn.session, deviceSecret: deviceSecret)

        // The extension: its own process, only the shared file.
        let extensionStore = try LocalStore.open(path: path)
        XCTAssertEqual(extensionStore.deviceUnlockStatus(), DeviceUnlockStatus(enabled: true, passwordRequired: false))
        XCTAssertThrowsError(try extensionStore.unlockWithDevice(deviceSecret: Data(repeating: 0, count: 32))) {
            XCTAssertEqual($0 as? OctaPassError, .DeviceUnlockFailed)
        }
        let session = try extensionStore.unlockWithDevice(deviceSecret: deviceSecret)
        XCTAssertEqual(try session.listItems(store: extensionStore).map(\.title), ["example.com"])
        session.lock()
        XCTAssertThrowsError(try session.listItems(store: extensionStore)) {
            XCTAssertEqual($0 as? OctaPassError, .Locked)
        }
    }

    func testToolsNeedNoVault() throws {
        let generated = try generatePassword(options: .random(
            length: 24, lowercase: true, uppercase: true, digits: true, symbols: false, avoidAmbiguous: true))
        XCTAssertEqual(generated.count, 24)
        XCTAssertGreaterThanOrEqual(estimateStrength(password: generated, userInputs: []).score, 3)
        XCTAssertEqual(try totpCode(totp: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", unixSeconds: 59).code, "287082")
        XCTAssertThrowsError(try normalizeSecretKey(text: "nope")) {
            XCTAssertEqual($0 as? OctaPassError, .InvalidSecretKey)
        }
        // What "Add login.example.com to this login?" adds (Session.otherLogins).
        XCTAssertEqual(websiteForPage(url: "https://login.example.com/sign-in?next=1"), "https://login.example.com")
        XCTAssertNil(websiteForPage(url: "androidapp://com.example.app"))
    }
}

private func base64url(_ text: String) -> Data? {
    var base64 = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
    return Data(base64Encoded: base64)
}
