import AuthenticationServices
import CryptoKit
import OctaPassCore
import OctaPassKeychain
import XCTest
@testable import OctaPassAutoFillKit

final class Loopback: HttpClient, @unchecked Sendable {
    let server = TestServer()
    func send(request: HttpRequest) throws -> HttpResponse { server.handle(request: request) }
}

/// The Keychain as the extension sees it, with a scripted Face ID.
final class FakeSecrets: AutoFillSecrets {
    var secretKey: String?
    var deviceSecret = Data()
    var cancel = false
    var prompts: [String] = []
    /// The stay-unlocked items the app kept, by name.
    var stayUnlocked: [String: Data] = [:]

    func secretKey(_ name: String) throws -> String? { secretKey }

    func stayUnlockedKey(_ name: String) throws -> Data? { stayUnlocked[name] }

    func deleteStayUnlockedKey(_ name: String) throws { stayUnlocked[name] = nil }

    func chipSecret(_ name: String, context: Data) throws -> Data { Data() }

    func deviceSecret(_ name: String, reason: String) throws -> Data {
        prompts.append(reason)
        if cancel { throw KeychainError.cancelled }
        return deviceSecret
    }
}

final class AutoFillVaultTests: XCTestCase {
    var directory: URL!
    let secrets = FakeSecrets()

    /// What the app leaves in the App Group: a signed-in account's store, `accounts.json`, a
    /// login with a one-time code, and device unlock turned on.
    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let api = try OctaPassServer(baseUrl: "https://octapass.test", http: Loopback())
        let signup = try api.startSignup(email: "ada@example.com", password: "correct horse")
        let signedIn = try signup.finish(
            verificationCode: XCTUnwrap(signup.devVerificationCode()), device: DeviceInfo(name: "iPhone", platform: "ios"))
        let account = SharedContainer.Account(tag: "abc", email: "ada@example.com", serverUrl: api.baseUrl())
        let store = try LocalStore.create(
            path: directory.appendingPathComponent(account.storeFile).path, serverUrl: api.baseUrl(), session: signedIn.session)
        try api.sync(accessToken: signedIn.tokens.accessToken, store: store)
        for (url, user) in [("https://github.com/login", "ada"), ("https://example.com", "lovelace")] {
            _ = try signedIn.session.saveLogin(store: store, draft: LoginDraft(
                itemId: nil, title: nil, url: url, username: user, password: "pw-\(user)", totp: "JBSWY3DPEHPK3PXP"))
        }
        secrets.deviceSecret = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        try store.enableDeviceUnlock(session: signedIn.session, deviceSecret: secrets.deviceSecret)
        secrets.secretKey = signup.secretKey()
        let accounts = #"{"accounts":[{"tag":"abc","email":"ada@example.com","serverUrl":"https://octapass.test/"}],"current":"abc"}"#
        try Data(accounts.utf8).write(to: directory.appendingPathComponent("accounts.json"))
    }

    override func tearDownWithError() throws {
        try FileManager.default.removeItem(at: directory)
    }

    func testNeedsASignedInApp() throws {
        try FileManager.default.removeItem(at: directory.appendingPathComponent("accounts.json"))
        XCTAssertThrowsError(try AutoFillVault(directory: directory, secrets: secrets)) {
            XCTAssertEqual($0 as? AutoFillError, .signedOut)
        }
    }

    func testUnlocksWithTheDeviceLockOrThePassword() throws {
        let vault = try AutoFillVault(directory: directory, secrets: secrets)
        XCTAssertTrue(vault.deviceUnlockEnabled)
        XCTAssertTrue(vault.deviceUnlockAvailable)
        XCTAssertThrowsError(try vault.logins(for: ["https://github.com"])) { XCTAssertEqual($0 as? AutoFillError, .locked) }

        secrets.cancel = true
        XCTAssertThrowsError(try vault.unlockWithDevice(reason: "Fill")) { XCTAssertEqual($0 as? AutoFillError, .cancelled) }
        secrets.cancel = false
        try vault.unlockWithDevice(reason: "Fill")
        XCTAssertEqual(secrets.prompts, ["Fill", "Fill"])
        XCTAssertTrue(vault.isUnlocked)
        vault.lock()
        XCTAssertFalse(vault.isUnlocked)

        XCTAssertThrowsError(try vault.unlock(password: "wrong")) { XCTAssertEqual($0 as? OctaPassError, .LoginFailed) }
        try vault.unlock(password: "correct horse")
        XCTAssertTrue(vault.isUnlocked)
    }

    /// Off in the app: the extension asks for the master password and says where to turn it on.
    /// Stay unlocked (plan 18): with the app's key for the current account in the shared Keychain,
    /// the extension opens the store and fills with no prompt. Without it, or with one that no
    /// longer opens the account (deleted then), it unlocks as before.
    func testFillsWithNoPromptWhileTheAppStaysUnlocked() throws {
        let vault = try AutoFillVault(directory: directory, secrets: secrets)
        XCTAssertEqual(vault.account.stayUnlockedName, "stayUnlocked.abc")
        XCTAssertFalse(try vault.unlockStayUnlocked(), "the setting is off in the app: no key")
        XCTAssertFalse(vault.isUnlocked)

        // What the app keeps when it unlocks with the setting on.
        try vault.unlockWithDevice(reason: "Fill")
        secrets.stayUnlocked["stayUnlocked.abc"] = try vault.store.stayUnlockedKey(session: XCTUnwrap(vault.session))
        secrets.prompts = []

        let later = try AutoFillVault(directory: directory, secrets: secrets)
        XCTAssertTrue(try later.unlockStayUnlocked())
        XCTAssertTrue(later.isUnlocked)
        XCTAssertEqual(secrets.prompts, [], "no prompt")
        XCTAssertEqual(try later.logins(for: ["https://github.com"]).map(\.username), ["ada"])
        XCTAssertEqual(try later.password(itemId: later.logins(for: ["https://github.com"])[0].itemId).password, "pw-ada")

        // Another account's key, or a damaged one: refused and deleted, then today's unlock.
        var damaged = try XCTUnwrap(secrets.stayUnlocked["stayUnlocked.abc"])
        damaged[1] ^= 1
        secrets.stayUnlocked["stayUnlocked.abc"] = damaged
        let third = try AutoFillVault(directory: directory, secrets: secrets)
        XCTAssertFalse(try third.unlockStayUnlocked())
        XCTAssertFalse(third.isUnlocked)
        XCTAssertNil(secrets.stayUnlocked["stayUnlocked.abc"])
        try third.unlockWithDevice(reason: "Fill")
        XCTAssertTrue(third.isUnlocked)
    }

    /// The autofill gate off (plan 03): while the app's vault is unlocked it keeps a fill key, and
    /// the extension fills with no prompt until the app locks (it deletes the key) or the key's
    /// deadline, the app's lock timer, passes (the extension deletes it).
    func testFillsWithNoPromptWhileTheAppIsUnlockedWithTheGateOff() throws {
        let vault = try AutoFillVault(directory: directory, secrets: secrets)
        XCTAssertEqual(vault.account.fillKeyName, "unlockedFill.abc")
        XCTAssertFalse(try vault.unlockWithFillKey(), "the gate is on, or the app is locked: no key")
        XCTAssertFalse(try vault.unlockWithoutPrompt())

        // What the app keeps while it's unlocked with the gate off.
        try vault.unlockWithDevice(reason: "Fill")
        let session = try XCTUnwrap(vault.session)
        let inAMinute = UInt64(Date().timeIntervalSince1970 * 1000) + 60_000
        secrets.stayUnlocked["unlockedFill.abc"] = try vault.store.fillKey(session: session, expiresAtMs: inAMinute)
        secrets.prompts = []

        let later = try AutoFillVault(directory: directory, secrets: secrets)
        XCTAssertTrue(try later.unlockWithoutPrompt())
        XCTAssertTrue(later.isUnlocked)
        XCTAssertEqual(secrets.prompts, [], "no prompt")
        XCTAssertEqual(try later.logins(for: ["https://github.com"]).map(\.username), ["ada"])
        XCTAssertNotNil(secrets.stayUnlocked["unlockedFill.abc"], "kept for the next fill")

        // Past the app's lock timer: it asks again, and the key goes.
        let aMomentAgo = UInt64(Date().timeIntervalSince1970 * 1000) - 1
        secrets.stayUnlocked["unlockedFill.abc"] = try vault.store.fillKey(session: session, expiresAtMs: aMomentAgo)
        let expired = try AutoFillVault(directory: directory, secrets: secrets)
        XCTAssertFalse(try expired.unlockWithoutPrompt())
        XCTAssertFalse(expired.isUnlocked)
        XCTAssertNil(secrets.stayUnlocked["unlockedFill.abc"])

        // A stay-unlocked key under the fill key's name isn't one: refused and deleted.
        secrets.stayUnlocked["unlockedFill.abc"] = try vault.store.stayUnlockedKey(session: session)
        let wrong = try AutoFillVault(directory: directory, secrets: secrets)
        XCTAssertFalse(try wrong.unlockWithFillKey())
        XCTAssertNil(secrets.stayUnlocked["unlockedFill.abc"])
    }

    func testDeviceUnlockOffInTheApp() throws {
        let store = try LocalStore.open(path: directory.appendingPathComponent("abc.opstore").path)
        try store.disableDeviceUnlock()
        let vault = try AutoFillVault(directory: directory, secrets: secrets)
        XCTAssertFalse(vault.deviceUnlockEnabled)
        XCTAssertFalse(vault.deviceUnlockAvailable)
        XCTAssertThrowsError(try vault.unlockWithDevice(reason: "Fill")) { XCTAssertEqual($0 as? AutoFillError, .passwordRequired) }
        XCTAssertEqual(secrets.prompts, [])
        try vault.unlock(password: "correct horse")
        XCTAssertTrue(vault.isUnlocked)
    }

    func testFillsPasswordsAndCodesForTheRequestingSite() throws {
        let vault = try AutoFillVault(directory: directory, secrets: secrets)
        try vault.unlockWithDevice(reason: "Fill")
        let urls = SystemRequests.urls(for: [
            ASCredentialServiceIdentifier(identifier: "github.com", type: .domain),
            ASCredentialServiceIdentifier(identifier: "https://github.com/session", type: .URL),
        ])
        XCTAssertEqual(urls, ["https://github.com", "https://github.com/session"])
        let logins = try vault.logins(for: urls)
        XCTAssertEqual(logins.map(\.username), ["ada"], "each login once")
        XCTAssertTrue(try vault.logins(for: ["https://github.com.evil.io"]).isEmpty)

        let credential = try vault.password(itemId: logins[0].itemId)
        XCTAssertEqual(credential.user, "ada")
        XCTAssertEqual(credential.password, "pw-ada")
        XCTAssertEqual(try vault.oneTimeCode(itemId: logins[0].itemId).count, 6)
        XCTAssertEqual(try vault.search("LOVE").map(\.username), ["lovelace"])
        XCTAssertEqual(try vault.search("").count, 2)
    }

    /// Default match rule: the page's host, the domains above it and the hosts below it. Another
    /// part of the domain is listed apart, and picking it there can add the page to the login.
    func testListsOtherPartsOfTheDomainApartAndAddsTheWebsite() throws {
        let vault = try AutoFillVault(directory: directory, secrets: secrets)
        try vault.unlockWithDevice(reason: "Fill")
        let session = try XCTUnwrap(vault.session)
        for (url, user) in [("https://shop.example.com/cart", "shopper"), ("https://a.login.example.com", "deep")] {
            _ = try session.saveLogin(store: vault.store, draft: LoginDraft(
                itemId: nil, title: nil, url: url, username: user, password: "pw-\(user)", totp: nil))
        }
        let page = ["https://login.example.com/sign-in"]
        XCTAssertEqual(Set(try vault.logins(for: page).compactMap(\.username)), ["lovelace", "deep"])
        let others = try vault.otherLogins(for: page)
        XCTAssertEqual(others.map(\.login.username), ["shopper"])
        XCTAssertEqual(others[0].host, "shop.example.com")
        XCTAssertEqual(others[0].site, "example.com")
        XCTAssertEqual(others[0].website, "https://login.example.com")
        XCTAssertEqual(others[0].websiteHost, "login.example.com")

        // The system may add the domain above the page: that's not a page whose subdomains match.
        let withParent = ["https://login.example.com/sign-in", "https://example.com"]
        XCTAssertEqual(Set(try vault.logins(for: withParent).compactMap(\.username)), ["lovelace", "deep"])
        XCTAssertEqual(try vault.otherLogins(for: withParent).map(\.login.username), ["shopper"])
        XCTAssertEqual(Set(try vault.logins(for: ["https://example.com"]).compactMap(\.username)), ["lovelace", "deep", "shopper"])
        XCTAssertTrue(try vault.otherLogins(for: ["https://github.com"]).isEmpty)

        // "Add login.example.com to this login?" → Add, twice: one website, the login unchanged.
        let shopper = others[0].login.itemId
        try vault.addWebsite(XCTUnwrap(others[0].website), to: shopper)
        try vault.addWebsite(XCTUnwrap(others[0].website), to: shopper)
        let later = try AutoFillVault(directory: directory, secrets: secrets)
        try later.unlockWithDevice(reason: "Fill")
        XCTAssertTrue(try later.logins(for: page).contains { $0.itemId == shopper })
        XCTAssertTrue(try later.otherLogins(for: page).isEmpty)
        let item = try XCTUnwrap(try later.session?.listItems(store: later.store).first { $0.itemId == shopper })
        XCTAssertEqual(item.urls, ["https://shop.example.com/cart", "https://login.example.com"])
        XCTAssertEqual(try later.password(itemId: shopper).user, "shopper")
        XCTAssertEqual(try later.password(itemId: shopper).password, "pw-shopper")
    }

    /// What Chrome and other apps send besides Safari's `.domain`: the page's full `.URL`, a bare
    /// host as a `.URL`, a domain with a scheme, empty identifiers, pages that aren't websites and
    /// an App ID. The websites among them get the logins Safari gets; the rest don't fail them.
    func testFillsWhateverFormTheBrowserNamesThePageIn() throws {
        let vault = try AutoFillVault(directory: directory, secrets: secrets)
        try vault.unlockWithDevice(reason: "Fill")
        let chrome = SystemRequests.urls(for: [
            ASCredentialServiceIdentifier(identifier: "", type: .URL),
            ASCredentialServiceIdentifier(identifier: "about:blank", type: .URL),
            ASCredentialServiceIdentifier(identifier: "https://www.github.com/login?return_to=https%3A%2F%2Fgithub.com%2F", type: .URL),
            ASCredentialServiceIdentifier(identifier: "github.com", type: .domain),
        ])
        XCTAssertEqual(chrome, ["https://www.github.com/login?return_to=https%3A%2F%2Fgithub.com%2F", "https://github.com"])
        XCTAssertEqual(try vault.logins(for: chrome).map(\.username), ["ada"])
        XCTAssertEqual(SystemRequests.urls(for: [
            ASCredentialServiceIdentifier(identifier: " github.com/login ", type: .URL),
            ASCredentialServiceIdentifier(identifier: "https://github.com", type: .domain),
            ASCredentialServiceIdentifier(identifier: "localhost:8080", type: .domain),
            ASCredentialServiceIdentifier(identifier: "chrome://newtab", type: .URL),
            ASCredentialServiceIdentifier(identifier: "github.com", type: .domain),
            ASCredentialServiceIdentifier(identifier: "github.com", type: .domain),
        ]), ["https://github.com/login", "https://github.com", "https://localhost:8080"])
        XCTAssertEqual(try vault.logins(for: SystemRequests.urls(for: [
            ASCredentialServiceIdentifier(identifier: "GitHub.com:443", type: .URL),
        ])).map(\.username), ["ada"])

        if #available(iOS 26.2, macOS 26.2, *) {
            XCTAssertEqual(SystemRequests.urls(for: [
                ASCredentialServiceIdentifier(identifier: "EQHXZ8M8AV.com.google.chrome.ios", type: .app),
                ASCredentialServiceIdentifier(identifier: "https://github.com/login", type: .URL),
            ]), ["https://github.com/login"])
        }

        // Something the core can't read as a website has no logins; it doesn't fail the others.
        XCTAssertEqual(try vault.logins(for: ["https://", "https://github.com"]).map(\.username), ["ada"])
        XCTAssertTrue(try vault.otherLogins(for: ["https://", "https://github.com"]).isEmpty)
    }

    func testTheSystemsParentDomainsAreNotPages() {
        XCTAssertEqual(
            AutoFillVault.pages(["https://m.example.com/a", "https://example.com", "https://www.example.com", "https://other.org", "example.app"]),
            ["https://m.example.com/a", "https://other.org", "example.app"])
        XCTAssertEqual(AutoFillVault.pages(["https://www.example.com", "https://example.com"]), ["https://www.example.com", "https://example.com"])
        XCTAssertEqual(AutoFillVault.pages(["https://example.com", "https://m.example.com/a"]), ["https://m.example.com/a"], "in any order")
    }

    func testRegistersAndSignsInWithPasskeys() throws {
        let vault = try AutoFillVault(directory: directory, secrets: secrets)
        try vault.unlockWithDevice(reason: "Create a passkey")
        let identity = ASPasskeyCredentialIdentity(
            relyingPartyIdentifier: "example.com", userName: "lovelace", credentialID: Data(), userHandle: Data([7, 7]),
            recordIdentifier: nil)
        let createHash = Data(SHA256.hash(data: Data(#"{"type":"webauthn.create"}"#.utf8)))
        let request = SystemRequests.creation(identity: identity, algorithms: [.ES256], excluded: [])
        let registration = try vault.register(request, clientDataHash: createHash)
        let created = SystemRequests.registration(registration, rpId: "example.com", clientDataHash: createHash)
        XCTAssertEqual(created.credentialID, registration.credentialId)
        XCTAssertThrowsError(try vault.register(
            SystemRequests.creation(identity: identity, algorithms: [.ES256], excluded: [registration.credentialId]),
            clientDataHash: createHash)) {
            XCTAssertEqual($0 as? OctaPassError, .PasskeyExcluded)
        }

        // A new extension process later: only the shared file.
        let later = try AutoFillVault(directory: directory, secrets: secrets)
        try later.unlockWithDevice(reason: "Sign in")
        let getHash = Data(SHA256.hash(data: Data(#"{"type":"webauthn.get"}"#.utf8)))
        let found = try later.passkeys(rpId: "example.com", clientDataHash: getHash, allowed: [])
        XCTAssertEqual(found.map(\.userName), ["lovelace"])
        let signed = try later.assertion(rpId: "example.com", clientDataHash: getHash, allowed: [], credentialId: found[0].credentialId)
        let credential = SystemRequests.assertion(signed, rpId: "example.com", clientDataHash: getHash)
        XCTAssertEqual(credential.userHandle, Data([7, 7]))

        let response = try JSONSerialization.jsonObject(with: Data(registration.responseJson.utf8)) as! [String: Any]
        let publicKey = try XCTUnwrap((response["response"] as? [String: Any])?["publicKey"] as? String)
        let key = try P256.Signing.PublicKey(derRepresentation: XCTUnwrap(Data(base64URL: publicKey)))
        let signature = try P256.Signing.ECDSASignature(derRepresentation: signed.signature)
        XCTAssertTrue(key.isValidSignature(signature, for: signed.authenticatorData + getHash))
        XCTAssertTrue(try later.passkeys(rpId: "other.example", clientDataHash: getHash, allowed: []).isEmpty)
    }
}

extension Data {
    init?(base64URL text: String) {
        var base64 = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
        self.init(base64Encoded: base64)
    }
}
