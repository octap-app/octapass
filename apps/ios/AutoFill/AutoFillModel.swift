import AuthenticationServices
import OctaPassAutoFillKit
import OctaPassCore
import OctaPassKeychain
import os

/// Why a request failed, for Console (`subsystem:app.octap.ios.autofill`): the error's name only,
/// never an item or a key.
private let log = Logger(subsystem: "app.octap.ios.autofill", category: "autofill")

/// What the system asked for, and how the extension answers once unlocked.
enum AutoFillTask {
    /// Pick a login for these sites (the QuickType bar's "Passwords", or a password field).
    case passwords(urls: [String])
    /// Pick a passkey or a login (`prepareCredentialList(for:requestParameters:)`).
    case passkeysOrPasswords(urls: [String], parameters: ASPasskeyCredentialRequestParameters)
    /// Pick a login's one-time code (iOS 18).
    case oneTimeCodes(urls: [String])
    /// The user picked a suggestion; fill it once unlocked.
    case credential(ASCredentialRequest)
    /// Create a passkey for a site.
    case registration(ASPasskeyCredentialRequest)
}

/// Answers to the system: the view controller turns them into `completeRequest` calls.
enum AutoFillAnswer {
    case password(ASPasswordCredential)
    case assertion(ASPasskeyAssertionCredential)
    case registration(ASPasskeyRegistrationCredential)
    case oneTimeCode(String)
    case cancel(ASExtensionError.Code)
}

@MainActor
final class AutoFillModel: ObservableObject {
    enum Phase: Equatable {
        case locked
        case unlocking
        case list
        case failed(String)
    }

    @Published var phase: Phase = .locked
    @Published var query = ""
    @Published var suggestions: [Login] = []
    /// Logins for other parts of the site's domain: listed apart, filled only when picked.
    @Published var others: [OtherPartLogin] = []
    /// After one of `others` is picked: whether to add the page's website to it before filling.
    @Published var offer: WebsiteOffer?
    @Published var passkeys: [PasskeyMatch] = []
    @Published var error: String?

    /// What's being answered. A picked suggestion that can't be filled becomes the list for its site.
    private(set) var task: AutoFillTask
    let vault: AutoFillVault?
    let deviceLock = DeviceLock.current()
    private let answer: (AutoFillAnswer) -> Void

    init(task: AutoFillTask, answer: @escaping (AutoFillAnswer) -> Void) {
        self.task = task
        self.answer = answer
        do {
            guard let directory = SharedContainer.url() else { throw AutoFillError.signedOut }
            vault = try AutoFillVault(directory: directory, secrets: Keychain())
        } catch {
            vault = nil
            phase = .failed(String(localized: "Sign in to the Octa Pass app first."))
        }
    }

    var email: String { vault?.account.email ?? "" }
    var canUseDevice: Bool { vault?.deviceUnlockAvailable == true && deviceLock.available }
    /// Device unlock is off in the app (not just due for the master password): say where it is.
    var suggestDeviceUnlock: Bool { vault?.deviceUnlockEnabled == false && deviceLock.available }
    /// "Touch ID", "Face ID" or the passcode; a Mac without Touch ID names its password, as the app does.
    var deviceLabel: String {
        #if os(macOS)
        if deviceLock.label == "Passcode" { return "your Mac’s password" }
        #endif
        return deviceLock.label
    }

    var deviceIcon: String {
        if deviceLock.label == "Touch ID" { return "touchid" }
        #if os(macOS)
        return "lock"
        #else
        return "faceid"
        #endif
    }

    var title: String {
        switch task {
        case .registration: String(localized: "Save a passkey")
        case .oneTimeCodes: String(localized: "One-time codes")
        default: "Octa Pass"
        }
    }

    /// With "Stay unlocked" on in the app (plan 18), the key in the shared Keychain opens the store
    /// and the extension fills with no prompt. Without it, or when it no longer opens the account,
    /// Face ID / Touch ID or the passcode right away, as the unlock screen does (plan 03); when
    /// the 14-day check is due, the master password.
    func start() {
        guard phase == .locked, let vault else { return }
        phase = .unlocking
        Task.detached { [vault] in
            let result = Result { try vault.unlockStayUnlocked() }
            await MainActor.run {
                switch result {
                case .success(true):
                    self.unlocked()
                case .failure(AutoFillError.passwordRequired):
                    self.phase = .locked
                    self.error = String(localized: "Enter your master password. It's needed every 14 days.")
                default:
                    self.phase = .locked
                    if self.canUseDevice { self.unlockWithDevice() }
                }
            }
        }
    }

    /// `provideCredentialWithoutUserInteraction`: a picked password or one-time code suggestion
    /// fills right away, with no screen, while "Stay unlocked" is on in the app (plan 18), as the
    /// screen would have done with no prompt. Otherwise, or when it can't, the system opens the
    /// screen (`prepareInterfaceToProvideCredential`). Passkeys always go through the screen.
    func fillWithoutUserInteraction() {
        guard case .credential(let request) = task, request.type != .passkeyAssertion, let vault else {
            return answer(.cancel(.userInteractionRequired))
        }
        Task.detached { [vault] in
            let opened = (try? vault.unlockStayUnlocked()) == true
            await MainActor.run {
                guard opened, let filled = try? self.fill(request, vault: vault) else {
                    return self.answer(.cancel(.userInteractionRequired))
                }
                if case .cancel = filled { return self.answer(.cancel(.userInteractionRequired)) }
                self.answer(filled)
            }
        }
    }

    func unlockWithDevice() {
        unlock { vault in try vault.unlockWithDevice(reason: String(localized: "Fill with Octa Pass")) }
    }

    func unlock(password: String) {
        unlock { vault in try vault.unlock(password: password) }
    }

    private func unlock(_ work: @escaping @Sendable (AutoFillVault) throws -> Void) {
        guard let vault else { return }
        phase = .unlocking
        error = nil
        Task.detached { [vault] in
            let result = Result { try work(vault) }
            await MainActor.run {
                switch result {
                case .success: self.unlocked()
                case .failure(AutoFillError.cancelled): self.phase = .locked
                case .failure(OctaPassError.LoginFailed):
                    self.phase = .locked
                    self.error = String(localized: "Wrong master password.")
                case .failure(AutoFillError.passwordRequired):
                    self.phase = .locked
                    self.error = String(localized: "Enter your master password. It's needed every 14 days.")
                case .failure:
                    self.phase = .locked
                    self.error = String(localized: "Couldn't unlock. Try your master password.")
                }
            }
        }
    }

    private func unlocked() {
        guard let vault else { return }
        do {
            switch task {
            case .passwords(let urls), .oneTimeCodes(let urls):
                suggestions = try vault.logins(for: urls)
                others = try vault.otherLogins(for: urls)
            case .passkeysOrPasswords(let urls, let parameters):
                suggestions = try vault.logins(for: urls)
                others = try vault.otherLogins(for: urls)
                passkeys = try vault.passkeys(
                    rpId: parameters.relyingPartyIdentifier, clientDataHash: parameters.clientDataHash,
                    allowed: parameters.allowedCredentials)
            case .credential(let request):
                guard let fallback = Self.listFallback(for: request) else { return answer(try fill(request, vault: vault)) }
                do {
                    return answer(try fill(request, vault: vault))
                } catch {
                    // The suggestion's login is gone, or the system kept an identity from an older
                    // list: show the list for its site instead of failing (plan 05).
                    task = fallback
                    return unlocked()
                }
            case .registration(let request):
                return answer(try register(request, vault: vault))
            }
            if case .oneTimeCodes = task {
                suggestions = suggestions.filter(\.hasTotp)
                others = others.filter(\.login.hasTotp)
            }
            phase = .list
        } catch OctaPassError.PasskeyExcluded {
            phase = .failed(String(localized: "A passkey for this account is already saved in Octa Pass."))
        } catch OctaPassError.PasskeyRpMismatch where task.isRegistration {
            // Not for a website (and not a browser extension's own passkey, which the core accepts).
            phase = .failed(String(localized: "Octa Pass saves passkeys for websites only. Save this one in Passwords or on a security key."))
        } catch {
            log.error("Couldn't answer \(String(describing: self.task.kind), privacy: .public): \(String(describing: error), privacy: .public)")
            phase = .failed(String(localized: "Octa Pass couldn't answer this request."))
        }
    }

    /// Every login matching the search, when the suggestions aren't the right ones.
    var searchResults: [Login] {
        guard !query.isEmpty, let vault, vault.isUnlocked else { return [] }
        let found = (try? vault.search(query)) ?? []
        return task.isOneTimeCodes ? found.filter(\.hasTotp) : found
    }

    func choose(_ login: Login) {
        guard let filled = fill(login) else { return }
        answer(filled)
    }

    /// A login for another part of the domain fills only when picked here. Then, when its vault can
    /// be changed, the extension asks whether to add this site to it before handing the credential
    /// to the system: the extension closes once it has, so there's no later moment to ask.
    func choose(_ other: OtherPartLogin) {
        guard let filled = fill(other.login) else { return }
        guard let website = other.website, let host = other.websiteHost else { return answer(filled) }
        offer = WebsiteOffer(itemId: other.login.itemId, website: website, host: host, answer: filled)
    }

    /// Add or Not now: either way the login fills. The website is saved to the shared store first,
    /// and the app uploads it on its next sync; if saving fails, the fill still goes through.
    func finish(_ offer: WebsiteOffer, add: Bool) {
        self.offer = nil
        if add { try? vault?.addWebsite(offer.website, to: offer.itemId) }
        answer(offer.answer)
    }

    private func fill(_ login: Login) -> AutoFillAnswer? {
        guard let vault else { return nil }
        do {
            if task.isOneTimeCodes {
                return .oneTimeCode(try vault.oneTimeCode(itemId: login.itemId))
            }
            let credential = try vault.password(itemId: login.itemId)
            return .password(ASPasswordCredential(user: credential.user, password: credential.password))
        } catch {
            self.error = String(localized: "This login can't be filled.")
            return nil
        }
    }

    func choose(_ passkey: PasskeyMatch) {
        guard let vault, case .passkeysOrPasswords(_, let parameters) = task else { return }
        do {
            var prf: PasskeyPrfRequest?
            if #available(iOS 18.0, macOS 15.0, *) { prf = SystemRequests.prf(parameters.extensionInput?.prf) }
            let signed = try vault.assertion(
                rpId: parameters.relyingPartyIdentifier, clientDataHash: parameters.clientDataHash,
                allowed: parameters.allowedCredentials, credentialId: passkey.credentialId, prf: prf)
            answer(.assertion(SystemRequests.assertion(
                signed, rpId: parameters.relyingPartyIdentifier, clientDataHash: parameters.clientDataHash)))
        } catch {
            self.error = String(localized: "This passkey can't sign in.")
        }
    }

    func cancel() {
        answer(.cancel(.userCanceled))
    }

    private func fill(_ request: ASCredentialRequest, vault: AutoFillVault) throws -> AutoFillAnswer {
        let itemId = request.credentialIdentity.recordIdentifier ?? ""
        switch request.type {
        case .password:
            let credential = try vault.password(itemId: itemId)
            return .password(ASPasswordCredential(user: credential.user, password: credential.password))
        case .passkeyAssertion:
            guard let request = request as? ASPasskeyCredentialRequest,
                  let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity
            else { return .cancel(.failed) }
            var prf: PasskeyPrfRequest?
            if #available(iOS 18.0, macOS 15.0, *), case .assertion(let input) = request.extensionInput {
                prf = SystemRequests.prf(input.prf)
            }
            let signed = try vault.assertion(
                rpId: identity.relyingPartyIdentifier, clientDataHash: request.clientDataHash, allowed: [],
                credentialId: identity.credentialID, prf: prf)
            return .assertion(SystemRequests.assertion(
                signed, rpId: identity.relyingPartyIdentifier, clientDataHash: request.clientDataHash))
        default:
            if #available(iOS 18.0, macOS 15.0, *), request.type == .oneTimeCode {
                return .oneTimeCode(try vault.oneTimeCode(itemId: itemId))
            }
            return .cancel(.failed)
        }
    }

    private func register(_ request: ASPasskeyCredentialRequest, vault: AutoFillVault) throws -> AutoFillAnswer {
        guard let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity else { return .cancel(.failed) }
        var excluded: [Data] = []
        var prf: PasskeyPrfRequest?
        if #available(iOS 18.0, macOS 15.0, *) {
            excluded = request.excludedCredentials?.map(\.credentialID) ?? []
            if case .registration(let input) = request.extensionInput { prf = SystemRequests.prf(input.prf) }
        }
        let registration = try vault.register(
            SystemRequests.creation(
                identity: identity, algorithms: request.supportedAlgorithms, excluded: excluded, prf: prf),
            clientDataHash: request.clientDataHash)
        return .registration(SystemRequests.registration(
            registration, rpId: identity.relyingPartyIdentifier, clientDataHash: request.clientDataHash))
    }
}

/// "Add login.example.com to this login?", with the credential that fills either way.
struct WebsiteOffer: Identifiable {
    let itemId: String
    let website: String
    let host: String
    let answer: AutoFillAnswer

    var id: String { itemId }
}

extension AutoFillModel {
    /// The list to show when a picked password or code suggestion can't be filled: the logins for
    /// its site, as if the user had opened the list there. Nil for passkeys.
    static func listFallback(for request: ASCredentialRequest) -> AutoFillTask? {
        let urls = SystemRequests.urls(for: [request.credentialIdentity.serviceIdentifier])
        if request.type == .password { return .passwords(urls: urls) }
        if #available(iOS 18.0, macOS 15.0, *), request.type == .oneTimeCode { return .oneTimeCodes(urls: urls) }
        return nil
    }
}

extension AutoFillTask {
    /// The kind of request, for the log: no sites, no names.
    var kind: String {
        switch self {
        case .passwords: "passwords"
        case .passkeysOrPasswords: "passkeys or passwords"
        case .oneTimeCodes: "one-time codes"
        case .credential: "credential"
        case .registration: "passkey registration"
        }
    }

    var isRegistration: Bool {
        if case .registration = self { true } else { false }
    }

    var isOneTimeCodes: Bool {
        if case .oneTimeCodes = self { true } else { false }
    }
}
