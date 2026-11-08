import Foundation
import OctaPassCore
import OctaPassKeychain

/// Where the extension's secrets come from: the shared Keychain in the app, a fake in tests.
public protocol AutoFillSecrets {
    /// The Secret Key, for unlocking with the master password.
    func secretKey(_ name: String) throws -> String?
    /// Shows Face ID / Touch ID or the passcode sheet, then returns the device-unlock secret.
    func deviceSecret(_ name: String, reason: String) throws -> Data
    /// The device chip's part of a local vault's key.
    func chipSecret(_ name: String, context: Data) throws -> Data
    /// The stay-unlocked key (plan 18), with no prompt: there while the app has "Stay unlocked"
    /// on, nil otherwise. Also the fill key, under its own name (plan 03, the autofill gate off).
    func stayUnlockedKey(_ name: String) throws -> Data?
    /// The key no longer opens the account, or has expired.
    func deleteStayUnlockedKey(_ name: String) throws
}

public extension AutoFillSecrets {
    func stayUnlockedKey(_ name: String) throws -> Data? { nil }
    func deleteStayUnlockedKey(_ name: String) throws {}
}

extension Keychain: AutoFillSecrets {
    public func secretKey(_ name: String) throws -> String? {
        try secret(name)
    }

    public func deviceSecret(_ name: String, reason: String) throws -> Data {
        try deviceSecret(name, reason: reason, context: .init())
    }
}

public enum AutoFillError: Error, Equatable {
    /// Nobody is signed in to the app.
    case signedOut
    /// Device unlock is off, or the master password is due (every 14 days, plan 03).
    case passwordRequired
    case cancelled
    case locked
}

/// A login that can fill the requesting site or app.
public struct Login: Equatable, Identifiable {
    public let itemId: String
    public let title: String
    public let username: String?
    /// The saved URL that matched, or the login's first URL.
    public let url: String?
    /// The site uses `http` while the login was saved for `https` (or the other way): warn.
    public let schemeMismatch: Bool
    public let hasTotp: Bool

    public var id: String { itemId }
}

/// A login saved for another part of the requesting site's domain (shop.example.com on
/// login.example.com). Never suggested with the matches: listed apart, filled only when picked.
public struct OtherPartLogin: Equatable, Identifiable {
    public let login: Login
    /// Where the login is saved, for its label: `shop.example.com` (no `www.`).
    public let host: String
    /// The domain both share, for the section's title: `example.com`.
    public let site: String
    /// The requesting page's website (`https://login.example.com`) to add to the login after
    /// it fills there. `nil` when the login's vault is read-only or the page isn't a website.
    public let website: String?

    public var id: String { login.itemId }

    /// The page's host as the offer names it: `login.example.com`.
    public var websiteHost: String? {
        website.flatMap { URL(string: $0)?.host() }.map(AutoFillVault.withoutWWW)
    }
}

/// The current account's shared store, as the extension sees it. Nothing here touches the
/// network: what the extension saves (new passkeys) waits in the store until the app uploads it.
public final class AutoFillVault {
    public let account: SharedContainer.Account
    let store: LocalStore
    let secrets: AutoFillSecrets
    var session: Session?

    public init(directory: URL, secrets: AutoFillSecrets) throws {
        guard let account = SharedContainer.currentAccount(in: directory) else { throw AutoFillError.signedOut }
        self.account = account
        self.secrets = secrets
        store = try LocalStore.open(path: directory.appendingPathComponent(account.storeFile).path)
    }

    deinit {
        session?.lock()
    }

    /// Turned on in the app's Settings, whether or not the master password is due.
    public var deviceUnlockEnabled: Bool { store.deviceUnlockStatus().enabled }

    public var deviceUnlockAvailable: Bool {
        let status = store.deviceUnlockStatus()
        return status.enabled && !status.passwordRequired
    }

    public var isUnlocked: Bool { session.map { !$0.isLocked() } ?? false }

    /// Stay unlocked (plan 18): opens the store with the key the app keeps in the shared
    /// Keychain, with no prompt. False when there's no key (the setting is off in the app, or the
    /// phone has no passcode) or it no longer opens the account (it's deleted then): unlock as
    /// before. Throws `passwordRequired` while the 14-day master password check is due.
    public func unlockStayUnlocked() throws -> Bool {
        guard let key = try secrets.stayUnlockedKey(account.stayUnlockedName) else { return false }
        do {
            session = try store.unlockStayUnlocked(key: key)
            return true
        } catch OctaPassError.PasswordRequired {
            throw AutoFillError.passwordRequired
        } catch OctaPassError.DeviceUnlockFailed {
            try? secrets.deleteStayUnlockedKey(account.stayUnlockedName)
            return false
        }
    }

    /// The autofill gate off (plan 03): while the app's vault is unlocked, the app keeps a fill key
    /// in the shared Keychain and the extension opens the store with it, with no prompt. False
    /// when there's none (the gate is on, the app is locked, stay unlocked is on, the phone has
    /// no passcode), it has expired with the app's lock timer, or it no longer opens the account
    /// (deleted then, as an expired one is): unlock as before. Throws `passwordRequired` while the
    /// 14-day master password check is due.
    public func unlockWithFillKey() throws -> Bool {
        guard let key = try secrets.stayUnlockedKey(account.fillKeyName) else { return false }
        do {
            guard let opened = try store.unlockFillKey(key: key) else {
                try? secrets.deleteStayUnlockedKey(account.fillKeyName)
                return false
            }
            session = opened
            return true
        } catch OctaPassError.PasswordRequired {
            throw AutoFillError.passwordRequired
        } catch OctaPassError.DeviceUnlockFailed {
            try? secrets.deleteStayUnlockedKey(account.fillKeyName)
            return false
        }
    }

    /// What opens the store without a prompt, if anything does: stay unlocked's key (plan 18),
    /// then the autofill gate's fill key (plan 03). Throws `passwordRequired` while the 14-day
    /// check is due.
    public func unlockWithoutPrompt() throws -> Bool {
        if try unlockStayUnlocked() { return true }
        return try unlockWithFillKey()
    }

    /// Face ID / Touch ID or the device passcode. Blocks while the system prompt is up.
    public func unlockWithDevice(reason: String) throws {
        guard deviceUnlockAvailable else { throw AutoFillError.passwordRequired }
        let secret: Data
        do {
            secret = try secrets.deviceSecret(account.deviceSecretName, reason: reason)
        } catch KeychainError.cancelled {
            throw AutoFillError.cancelled
        }
        session = try store.unlockWithDevice(deviceSecret: secret)
    }

    /// The master password, with the Secret Key the app keeps in the shared Keychain. Runs
    /// Argon2id (64 MiB by default), within the extension's memory limit.
    public func unlock(password: String) throws {
        if store.isLocal() {
            let chip = try account.chipContext.map { try secrets.chipSecret(account.chipKeyName, context: $0) }
            session = try store.unlockLocal(password: password, chipSecret: chip)
            return
        }
        guard let secretKey = try secrets.secretKey(account.secretKeyName) else { throw AutoFillError.signedOut }
        session = try store.unlockWithPassword(password: password, secretKey: secretKey)
    }

    public func lock() {
        session?.lock()
        session = nil
    }

    func unlocked() throws -> Session {
        guard let session, !session.isLocked() else { throw AutoFillError.locked }
        return session
    }

    /// Logins for the requesting sites, best match first, each login once: saved for the page's
    /// host, a domain above it or a host below it. Not other parts of its domain (`otherLogins`).
    public func logins(for urls: [String]) throws -> [Login] {
        let session = try unlocked()
        var seen = Set<String>()
        return try Self.pages(urls).flatMap { page in try Self.ifWebsite { try session.matchLogins(store: store, url: page) } }
            .filter { seen.insert($0.item.itemId).inserted }
            .filter { Self.fillsPassword($0.item) }
            .map { Login(
                itemId: $0.item.itemId, title: $0.item.title, username: $0.item.username, url: $0.url,
                schemeMismatch: $0.schemeMismatch, hasTotp: $0.item.hasTotp) }
    }

    /// Logins saved for other parts of the requesting sites' domains, by host, each once and none
    /// that `logins(for:)` already lists. One tap away, never suggested.
    public func otherLogins(for urls: [String]) throws -> [OtherPartLogin] {
        let session = try unlocked()
        var seen = Set(try logins(for: urls).map(\.itemId))
        return try Self.pages(urls).flatMap { page in
            let website = websiteForPage(url: page)
            return try Self.ifWebsite { try session.otherLogins(store: store, url: page) }.map { (page: website, other: $0) }
        }
        .filter { seen.insert($0.other.item.itemId).inserted }
        .filter { Self.fillsPassword($0.other.item) }
        .map { page, other in OtherPartLogin(
            login: Login(
                itemId: other.item.itemId, title: other.item.title, username: other.item.username, url: other.url,
                schemeMismatch: other.schemeMismatch, hasTotp: other.item.hasTotp),
            host: other.host, site: other.site, website: other.canAddWebsite ? page : nil) }
    }

    /// Adds the page's website to a login the user filled from another part of its domain, so it's
    /// suggested there next time. Saved to the shared store; the app uploads it on its next sync.
    /// Nothing changes when the login already has that website.
    public func addWebsite(_ website: String, to itemId: String) throws {
        _ = try unlocked().saveLogin(store: store, draft: LoginDraft(
            itemId: itemId, title: nil, url: website, username: nil, password: nil, totp: nil))
    }

    /// The system may add the domains above the page (`[m.example.com, example.com]`,
    /// `prepareCredentialList(for:)`); Safari lists the page first, other browsers not always. A
    /// domain above another one named is that page's parent, not another page: its logins are
    /// already "a domain above" the page's, and asking for it too would suggest the logins of every
    /// other part of the domain.
    static func pages(_ urls: [String]) -> [String] {
        let hosts = urls.map(host)
        return zip(urls, hosts).filter { _, host in
            guard let host else { return true }
            return !hosts.contains { $0?.hasSuffix("." + host) == true }
        }
        .map(\.0)
    }

    /// One page the core can't read as a website (`InvalidUrl`) has no logins. It doesn't fail
    /// the others the system named with it, nor the list (the user can still search).
    static func ifWebsite<T>(_ work: () throws -> [T]) throws -> [T] {
        do {
            return try work()
        } catch OctaPassError.InvalidUrl {
            return []
        }
    }

    static func host(_ url: String) -> String? {
        URL(string: url)?.host()?.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: ".")).nonEmpty
            .map(withoutWWW)
    }

    static func withoutWWW(_ host: String) -> String {
        host.hasPrefix("www.") ? String(host.dropFirst(4)) : host
    }

    /// Every login whose title, user name or URL contains `query` (all of them when it's empty),
    /// for filling a site that doesn't match.
    public func search(_ query: String) throws -> [Login] {
        let session = try unlocked()
        let needle = query.trimmingCharacters(in: .whitespaces).lowercased()
        return try session.listItems(store: store)
            .filter { $0.itemType == "login" || $0.itemType == "password" }
            .filter { Self.fillsPassword($0) }
            .filter { item in
                needle.isEmpty || ([item.title, item.username ?? ""] + item.urls).contains { $0.lowercased().contains(needle) }
            }
            .map { Login(
                itemId: $0.itemId, title: $0.title, username: $0.username, url: $0.urls.first,
                schemeMismatch: false, hasTotp: $0.hasTotp) }
    }

    /// Whether a login belongs in a password list. One made by saving a passkey has no password:
    /// picked there, it would fill an empty one, so it's offered only through its passkey.
    static func fillsPassword(_ item: ItemSummary) -> Bool {
        item.hasPassword || !item.hasPasskey
    }

    public func password(itemId: String) throws -> (user: String, password: String) {
        let item = try unlocked().getItem(store: store, itemId: itemId)
        return (item.login?.username ?? "", item.login?.password ?? "")
    }

    public func oneTimeCode(itemId: String) throws -> String {
        try unlocked().totpCode(store: store, itemId: itemId).code
    }

    /// The saved passkeys for `rpId` (only those in `allowed`, when it isn't empty).
    public func passkeys(rpId: String, clientDataHash: Data, allowed: [Data]) throws -> [PasskeyMatch] {
        try unlocked().findPasskeys(
            store: store,
            request: PasskeyAssertionRequest(rpId: rpId, allowedCredentials: allowed, challenge: Data(), prf: nil),
            client: .hash(clientDataHash: clientDataHash))
    }

    /// Signs the system's `clientDataHash` with the chosen passkey, with the PRF extension's
    /// outputs when `prf` asks and the passkey has a PRF secret.
    public func assertion(
        rpId: String, clientDataHash: Data, allowed: [Data], credentialId: Data, prf: PasskeyPrfRequest? = nil
    ) throws -> PasskeyAssertion {
        try unlocked().getPasskeyAssertion(
            store: store,
            request: PasskeyAssertionRequest(rpId: rpId, allowedCredentials: allowed, challenge: Data(), prf: prf),
            client: .hash(clientDataHash: clientDataHash),
            credentialId: credentialId)
    }

    /// Creates a passkey and saves it to the store before returning, so a passkey the site
    /// accepted is never lost; the app uploads it on its next sync.
    public func register(_ request: PasskeyCreationRequest, clientDataHash: Data) throws -> PasskeyRegistration {
        try unlocked().createPasskey(store: store, request: request, client: .hash(clientDataHash: clientDataHash))
    }
}

private extension String {
    var nonEmpty: String? { isEmpty ? nil : self }
}
