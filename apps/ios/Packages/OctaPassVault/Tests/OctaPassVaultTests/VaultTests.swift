import Foundation
import OctaPassVault
import XCTest

/// The Keychain and the device lock, in memory, as the app's Keychain code would answer.
final class TestPlatform: NativePlatform, @unchecked Sendable {
    private let lock = NSLock()
    private var secrets: [String: String] = [:]
    private var deviceSecrets: [String: Data] = [:]
    private var stayUnlocked: [String: Data] = [:]
    private(set) var identities: [CredentialIdentity] = []
    /// A phone with a passcode; false is one without, where stay unlocked can't be kept.
    var passcode = true

    func secret(name: String) throws -> String? { lock.withLock { secrets[name] } }
    func setSecret(name: String, value: String) throws { lock.withLock { secrets[name] = value } }
    func deleteSecret(name: String) throws { _ = lock.withLock { secrets.removeValue(forKey: name) } }
    func deviceLock() -> DeviceLock { DeviceLock(available: passcode, label: passcode ? "Face ID" : "Passcode") }
    func storeDeviceSecret(name: String, secret: Data) throws { lock.withLock { deviceSecrets[name] = secret } }

    func deviceSecret(name: String, reason: String) throws -> Data {
        guard let secret = lock.withLock({ deviceSecrets[name] }) else {
            throw VaultError.Failed(code: .deviceUnlockFailed, reason: "no secret")
        }
        return secret
    }

    func deleteDeviceSecret(name: String) throws { _ = lock.withLock { deviceSecrets.removeValue(forKey: name) } }

    func verifyUser(reason: String) throws {
        throw VaultError.Failed(code: .deviceUnlockUnsupported, reason: "not in tests")
    }

    func storeStayUnlockedKey(name: String, key: Data) throws {
        guard passcode else { throw VaultError.Failed(code: .deviceUnlockUnsupported, reason: "no passcode") }
        lock.withLock { stayUnlocked[name] = key }
    }

    func stayUnlockedKey(name: String) throws -> Data? { lock.withLock { stayUnlocked[name] } }
    func deleteStayUnlockedKey(name: String) throws { _ = lock.withLock { stayUnlocked.removeValue(forKey: name) } }
    /// Stay unlocked's keys, not the autofill gate's fill keys kept in the same kind of item.
    var stayUnlockedKeys: Int { lock.withLock { stayUnlocked.keys.filter { $0.hasPrefix("stayUnlocked.") }.count } }
    var fillKeys: Int { lock.withLock { stayUnlocked.keys.filter { $0.hasPrefix("unlockedFill.") }.count } }
    func chipAvailable() -> Bool { false }
    func createChipKey(name: String) throws -> ChipKey? { nil }
    func chipSecret(name: String, context: Data) throws -> Data { Data() }
    func deleteChipKey(name: String) throws {}
    func lowMemory() -> Bool { true }
    func backupFolderFiles(folder: String) throws -> [String] { [] }
    func writeBackupFile(folder: String, name: String, source: String) throws {}
    func deleteBackupFile(folder: String, name: String) throws {}
    func setCredentialIdentities(identities: [CredentialIdentity]) throws { lock.withLock { self.identities = identities } }
}

final class TestObserver: VaultObserver, @unchecked Sendable {
    private let lock = NSLock()
    private(set) var sessions: [SessionSnapshot] = []
    private(set) var itemChanges = 0
    private(set) var sharingChanges = 0

    func sessionChanged(snapshot: SessionSnapshot) { lock.withLock { sessions.append(snapshot) } }
    func itemsChanged() { lock.withLock { itemChanges += 1 } }
    func syncChanged(state: SyncState) {}
    func sharingChanged() { lock.withLock { sharingChanges += 1 } }
}

/// One phone: its own App Group folder and Keychain.
final class Phone {
    let vault: OctaPassVault
    let platform = TestPlatform()
    let observer = TestObserver()
    let email: String
    let directory: URL

    init(email: String) throws {
        self.email = email
        directory = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        vault = try OctaPassVault(
            config: VaultConfig(
                dataDir: directory.appending(path: "group").path,
                tempDir: directory.appending(path: "tmp").path,
                deviceName: "Test iPhone",
                platform: .ios,
                pwnedPasswordsUrl: VaultTests.server,
                webVaultUrl: "https://vault.octap.app",
                defaultServerUrl: "https://vault.octap.app"),
            platform: platform, observer: observer)
    }

    deinit { try? FileManager.default.removeItem(at: directory) }

    /// The app started again on this phone: the same folder and Keychain, nothing in memory.
    func relaunch() throws -> OctaPassVault {
        try OctaPassVault(
            config: VaultConfig(
                dataDir: directory.appending(path: "group").path,
                tempDir: directory.appending(path: "tmp").path,
                deviceName: "Test iPhone",
                platform: .ios,
                pwnedPasswordsUrl: VaultTests.server,
                webVaultUrl: "https://vault.octap.app",
                defaultServerUrl: "https://vault.octap.app"),
            platform: platform, observer: TestObserver())
    }

    /// Signs up on the development server, which hands back the email code.
    @discardableResult
    func signUp() async throws -> RecoveryKit {
        let started = try await vault.startSignup(serverUrl: VaultTests.server, email: email, password: VaultTests.password)
        let code = try XCTUnwrap(started.devVerificationCode)
        return try await vault.finishSignup(signupId: started.signupId, verificationCode: code)
    }

    func personalVault() async throws -> String {
        try await vault.listVaults().first { $0.vaultType == .personal }!.id
    }

    func titles(_ filter: ItemFilter = ItemFilter(vaultId: nil, itemType: nil, query: nil, trash: false, favorites: false, passkeys: false)) async throws -> [String] {
        try await vault.listItems(filter: filter).map(\.title).sorted()
    }
}

func errorCode(_ error: Error) -> ErrorCode? {
    guard case let .Failed(code, _) = error as? VaultError else { return nil }
    return code
}

func expectFailure<T>(_ code: ErrorCode, _ call: () async throws -> T, file: StaticString = #filePath, line: UInt = #line) async {
    do {
        _ = try await call()
        XCTFail("expected \(code)", file: file, line: line)
    } catch {
        XCTAssertEqual(errorCode(error), code, file: file, line: line)
    }
}

func login(_ title: String, vault: String, username: String, password: String) -> ItemDraft {
    var draft = newItemDraft(itemType: .login, vaultId: vault)
    draft.title = title
    draft.urls = ["https://\(title.lowercased()).example"]
    draft.details = .login(login: LoginDetails(
        username: username, password: password, totp: nil, notes: nil, passkeys: [], recovery: nil,
        customFields: [], passwordHistory: []))
    return draft
}

final class VaultTests: XCTestCase {
    /// The development server `test-swift.sh` started.
    static let server = ProcessInfo.processInfo.environment["OCTAPASS_TEST_SERVER"] ?? "http://127.0.0.1:8080"
    static let password = "correct horse battery staple"

    func unique(_ name: String) -> String { "\(name)-\(UUID().uuidString.prefix(8).lowercased())@example.com" }

    func testSignUpSignInAndTwoStep() async throws {
        let phone = try Phone(email: unique("ada"))
        XCTAssertEqual(phone.vault.snapshot().status, .signedOut)
        let kit = try await phone.signUp()
        XCTAssertTrue(kit.secretKey.hasPrefix("OP1-"))
        XCTAssertEqual(phone.vault.snapshot().status, .unlocked)
        XCTAssertEqual(phone.observer.sessions.last?.status, .unlocked)

        phone.vault.lock()
        XCTAssertEqual(phone.vault.snapshot().status, .locked)
        await expectFailure(.invalidCredentials) { try await phone.vault.unlock(password: "wrong") }
        try await phone.vault.unlock(password: Self.password)
        try await phone.vault.enableDeviceUnlock()
        phone.vault.lock()
        try await phone.vault.unlockWithDevice()
        XCTAssertEqual(phone.vault.snapshot().status, .unlocked)

        // Two-step sign-in on; a new phone then needs the second step.
        let setup = try await phone.vault.startTotpSetup(password: Self.password)
        let code = try totpCode(totp: setup.secret, atMs: nil).code
        let confirmed = try await phone.vault.confirmTotpSetup(code: code)
        let recoveryCodes = try XCTUnwrap(confirmed)
        XCTAssertFalse(recoveryCodes.isEmpty)

        let tablet = try Phone(email: phone.email)
        let result = try await tablet.vault.signIn(serverUrl: Self.server, email: phone.email, password: Self.password, secretKey: kit.secretKey)
        guard case let .twoStepRequired(methods) = result else { return XCTFail("expected a second step") }
        XCTAssertEqual(methods, [.totp, .recoveryCode])
        await expectFailure(.invalidTwoStepCode) { try await tablet.vault.finishTwoStep(proof: .totp(code: "000000")) }
        try await tablet.vault.finishTwoStep(proof: .recoveryCode(code: recoveryCodes[0]))
        XCTAssertEqual(tablet.vault.snapshot().status, .unlocked)
        let devices = try await tablet.vault.listDevices()
        XCTAssertEqual(devices.count, 2)
        let log = try await tablet.vault.securityLog()
        XCTAssertTrue(log.contains { $0.eventType == "two-step-enabled" })

        try await tablet.vault.signOut()
        XCTAssertEqual(tablet.vault.snapshot().status, .signedOut)
        try await phone.vault.deleteAccount(confirmEmail: phone.email, password: Self.password)
        XCTAssertEqual(phone.vault.snapshot().status, .signedOut)
    }

    /// Stay unlocked (plan 18): on for a new install, the key kept after the sign-up, the next
    /// start opens with no prompt, "Lock now" holds until the user unlocks, off forgets the key.
    func testStaysUnlockedWhileThePhoneHasAPasscode() async throws {
        let phone = try Phone(email: unique("hedy"))
        XCTAssertTrue(phone.vault.settings().stayUnlocked, "on by default for a new install")
        try await phone.signUp()
        // The key is kept on its own thread after the unlock.
        try await eventually { phone.vault.stayUnlockedStatus().enrolled }
        let status = phone.vault.stayUnlockedStatus()
        XCTAssertTrue(status.on)
        XCTAssertTrue(status.available)
        XCTAssertFalse(status.passwordRequired)

        // "Lock now" holds: the next attempt doesn't open, until the user unlocks.
        phone.vault.lock()
        let held = try await phone.vault.unlockStayUnlocked()
        XCTAssertFalse(held)
        XCTAssertEqual(phone.vault.snapshot().status, .locked)

        // The app starts again: no prompt.
        let started = try phone.relaunch()
        XCTAssertEqual(started.snapshot().status, .locked)
        let opened = try await started.unlockStayUnlocked()
        XCTAssertTrue(opened)
        XCTAssertEqual(started.snapshot().status, .unlocked)
        let vaults = try await started.listVaults()
        XCTAssertFalse(vaults.isEmpty)

        // Off: the key goes, and the next start asks.
        var settings = started.settings()
        settings.stayUnlocked = false
        try started.updateSettings(settings: settings)
        XCTAssertEqual(phone.platform.stayUnlockedKeys, 0)
        XCTAssertFalse(started.stayUnlockedStatus().enrolled)
        let off = try phone.relaunch()
        let openedOff = try await off.unlockStayUnlocked()
        XCTAssertFalse(openedOff)
        XCTAssertEqual(off.snapshot().status, .locked)
    }

    /// No passcode: no key is kept and the phone locks as before (plan 18, rule 5).
    func testWithoutAPasscodeItFallsBack() async throws {
        let phone = try Phone(email: unique("ida"))
        phone.platform.passcode = false
        try await phone.signUp()
        try await Task.sleep(for: .milliseconds(500))
        let status = phone.vault.stayUnlockedStatus()
        XCTAssertTrue(status.on)
        XCTAssertFalse(status.available)
        XCTAssertFalse(status.enrolled)
        XCTAssertEqual(phone.platform.stayUnlockedKeys, 0)
        let started = try phone.relaunch()
        let opened = try await started.unlockStayUnlocked()
        XCTAssertFalse(opened)
        XCTAssertEqual(started.snapshot().status, .locked)
    }

    /// The autofill gate off (plan 03), with stay unlocked off: the app keeps a fill key for the
    /// AutoFill extension only while its vault is unlocked; "Ask on every fill" on again removes it.
    func testTheAutofillGateOffKeepsAFillKeyWhileUnlocked() async throws {
        let phone = try Phone(email: unique("joan"))
        try await phone.signUp()
        XCTAssertTrue(phone.vault.settings().deviceAuthOnAutofill, "on by default")
        try await phone.vault.enableDeviceUnlock()
        var settings = phone.vault.settings()
        settings.stayUnlocked = false
        try phone.vault.updateSettings(settings: settings)
        try await eventually { phone.platform.fillKeys == 0 }
        XCTAssertFalse(phone.vault.fillsWithoutPrompt(), "every fill asks")

        settings.deviceAuthOnAutofill = false
        try phone.vault.updateSettings(settings: settings)
        XCTAssertEqual(phone.platform.fillKeys, 1)
        XCTAssertTrue(phone.vault.fillsWithoutPrompt())

        phone.vault.lock()
        XCTAssertEqual(phone.platform.fillKeys, 0, "a locked vault always asks")
        XCTAssertFalse(phone.vault.fillsWithoutPrompt())

        try await phone.vault.unlock(password: VaultTests.password)
        try await eventually { phone.platform.fillKeys == 1 }
        settings = phone.vault.settings()
        settings.deviceAuthOnAutofill = true
        try phone.vault.updateSettings(settings: settings)
        XCTAssertEqual(phone.platform.fillKeys, 0)
    }

    func eventually(_ condition: () -> Bool, file: StaticString = #filePath, line: UInt = #line) async throws {
        for _ in 0..<50 where !condition() { try await Task.sleep(for: .milliseconds(100)) }
        XCTAssertTrue(condition(), "never happened", file: file, line: line)
    }

    func testItemsOfEveryTypeAndAttachments() async throws {
        let phone = try Phone(email: unique("grace"))
        try await phone.signUp()
        let personal = try await phone.personalVault()

        let github = try await phone.vault.saveItem(draft: login("GitHub", vault: personal, username: "grace", password: "hunter2"))
        XCTAssertEqual(github.subtitle, "grace")
        let wifi = try await phone.vault.saveItem(draft: XCTUnwrap(scannedDraft(text: "WIFI:T:WPA;S:Home;P:wifi-pass;;", vaultId: personal)))
        XCTAssertEqual(wifi.wifi?.ssid, "Home")
        XCTAssertEqual(qrChoices(item: wifi).map(\.id), ["wifi", "password"])

        var bankDraft = newItemDraft(itemType: .bankAccount, vaultId: personal)
        bankDraft.title = "Savings"
        bankDraft.details = .structured(itemType: .bankAccount, structured: StructuredDetails(
            values: [FieldValue(key: "bankName", value: "Example Bank"), FieldValue(key: "accountHolder", value: "Grace"),
                     FieldValue(key: "iban", value: "DE89 3704 0044 0532 0130 00"), FieldValue(key: "pin", value: "0000")],
            addresses: [], fields: [], templateId: nil, templateName: nil, notes: nil, customFields: [], passwordHistory: []))
        let bank = try await phone.vault.saveItem(draft: bankDraft)
        XCTAssertEqual(bank.subtitle, "Example Bank")
        XCTAssertEqual(qrChoices(item: bank).map(\.id), ["payment", "iban"])
        XCTAssertFalse(qrChoices(item: bank).contains { $0.text.contains("0000") })
        XCTAssertEqual(fieldSpecs(itemType: .bankAccount).prefix(3).map(\.key), ["bankName", "accountHolder", "accountType"])

        var note = newItemDraft(itemType: .secureNote, vaultId: personal)
        note.title = "Ideas"
        note.details = .secureNote(note: SecureNoteDetails(notes: "Write more tests"))
        let savedNote = try await phone.vault.saveItem(draft: note)

        var card = newItemDraft(itemType: .card, vaultId: personal)
        card.title = "Visa"
        card.details = .card(card: CardDetails(cardholder: "Grace", number: "4111 1111 1111 1111", expiry: "01/30", cvv: "123", pin: nil, brand: nil, notes: nil))
        let savedCard = try await phone.vault.saveItem(draft: card)
        XCTAssertEqual(savedCard.subtitle, "Visa ending 1111")

        var identity = newItemDraft(itemType: .identity, vaultId: personal)
        identity.title = "Me"
        identity.details = .identity(identity: IdentityDetails(firstName: "Grace", lastName: "Hopper", email: "grace@example.com", phone: nil, address: nil, birthDate: nil, notes: nil))
        try await phone.vault.saveItem(draft: identity)

        var document = newItemDraft(itemType: .document, vaultId: personal)
        document.title = "Lease"
        document.details = .document(document: DocumentDetails(notes: "signed"))
        let lease = try await phone.vault.saveItem(draft: document)

        var invalid = newItemDraft(itemType: .login, vaultId: personal)
        invalid.title = " "
        XCTAssertEqual(validateDraft(draft: invalid).map(\.messageKey), ["validation.titleRequired"])
        await expectFailure(.invalidInput) { try await phone.vault.saveItem(draft: invalid) }

        // Edit: the old password goes into the history.
        var edit = itemDraft(item: github)
        guard case var .login(details) = edit.details else { return XCTFail("a login") }
        details.password = "new-password"
        edit.details = .login(login: details)
        let edited = try await phone.vault.saveItem(draft: edit)
        guard case let .login(after) = edited.details else { return XCTFail("a login") }
        XCTAssertEqual(after.passwordHistory.first?.password, "hunter2")
        let favourite = try await phone.vault.setFavorite(id: github.id, favorite: true)
        XCTAssertTrue(favourite.favorite)

        let titles = try await phone.titles()
        XCTAssertEqual(titles, ["GitHub", "Home", "Ideas", "Lease", "Me", "Savings", "Visa"])
        let sections = try await phone.vault.arrangeItems(
            filter: ItemFilter(vaultId: nil, itemType: nil, query: nil, trash: false, favorites: false, passkeys: false),
            sort: .name, grouping: .type)
        XCTAssertEqual(sections.map(\.key), ["login", "card", "identity", "secureNote", "wifi", "document", "bankAccount"])
        let found = try await phone.titles(ItemFilter(vaultId: nil, itemType: nil, query: "HOPPER", trash: false, favorites: false, passkeys: false))
        XCTAssertEqual(found, ["Me"])

        try await phone.vault.deleteItem(id: savedNote.id)
        let trash = try await phone.titles(ItemFilter(vaultId: nil, itemType: nil, query: nil, trash: true, favorites: false, passkeys: false))
        XCTAssertEqual(trash, ["Ideas"])
        try await phone.vault.restoreItem(id: savedNote.id)

        // A file from the picker, opened for Quick Look, then removed.
        let picked = phone.directory.appending(path: "lease.pdf")
        try FileManager.default.createDirectory(at: phone.directory, withIntermediateDirectories: true)
        try Data("%PDF-1.7 lease".utf8).write(to: picked)
        let withFile = try await phone.vault.addAttachment(itemId: lease.id, path: picked.path, name: "lease.pdf", mediaType: "application/pdf")
        let file = try XCTUnwrap(withFile.attachments.first)
        let opened = try await phone.vault.openAttachment(itemId: lease.id, attachmentId: file.id)
        XCTAssertEqual(try Data(contentsOf: URL(filePath: opened)), Data("%PDF-1.7 lease".utf8))
        phone.vault.closeAttachment(path: opened)
        XCTAssertFalse(FileManager.default.fileExists(atPath: opened))
        try await phone.vault.sync()
        XCTAssertEqual(phone.vault.syncState().pendingFiles, 0)
        let withoutFile = try await phone.vault.removeAttachment(itemId: lease.id, attachmentId: file.id)
        XCTAssertTrue(withoutFile.attachments.isEmpty)
    }

    func testSshKeysAndEnvironments() async throws {
        let phone = try Phone(email: unique("linus"))
        try await phone.signUp()
        let personal = try await phone.personalVault()

        let made = try await phone.vault.generateSshKey(kind: .ed25519, comment: "me@mac")
        var draft = newItemDraft(itemType: .sshKey, vaultId: personal)
        guard case let .sshKey(empty) = draft.details else { return XCTFail("an SSH key draft") }
        draft.details = .sshKey(key: withSshKey(details: empty, key: made, passphrase: nil))
        let key = try await phone.vault.saveItem(draft: draft)
        XCTAssertEqual(key.title, "me@mac", "named after its comment")
        guard case let .sshKey(details) = key.details else { return XCTFail("typed as an SSH key") }
        XCTAssertEqual(sshKeyTypeLabel(details: details), "Ed25519")
        XCTAssertTrue(authorizedKeysLine(details: details).hasSuffix(" me@mac"))
        await expectFailure(.sshPublicKeyOnly) { try await phone.vault.readSshKey(text: authorizedKeysLine(details: details), passphrase: nil) }

        var environment = newItemDraft(itemType: .environment, vaultId: personal)
        environment.title = "Shop"
        let merged = try mergeDotenv(variables: [], text: "API_KEY=abc\nDEBUG=1\n")
        XCTAssertEqual(merged.count, 2)
        environment.details = .environment(environment: EnvironmentDetails(project: "shop-api", projectName: nil, stage: "production", variables: merged.variables, notes: nil))
        let saved = try await phone.vault.saveItem(draft: environment)
        XCTAssertEqual(saved.subtitle, "shop-api · production")
        guard case let .environment(variables) = saved.details else { return XCTFail("typed as an environment") }
        XCTAssertEqual(try environmentDotenv(details: variables), "API_KEY=abc\nDEBUG=1\n")
        XCTAssertTrue(isProductionStage(stage: "production"))
    }

    func testSharingAVaultBetweenTwoAccounts() async throws {
        let alice = try Phone(email: unique("alice"))
        let bob = try Phone(email: unique("bob"))
        try await alice.signUp()
        try await bob.signUp()

        let lookup = try await alice.vault.lookupAccount(email: bob.email)
        let bobsOwn = try await bob.vault.myFingerprint()
        XCTAssertEqual(lookup.fingerprint, bobsOwn)
        try await alice.vault.markVerified(account: lookup)
        let shared = try await alice.vault.createVault(name: "Family recipes")
        try await alice.vault.addMember(vaultId: shared.id, account: lookup, role: .write)
        let pasta = try await alice.vault.saveItem(draft: login("Pasta", vault: shared.id, username: "chef", password: "al-dente"))
        let members = try await alice.vault.listMembers(vaultId: shared.id)
        XCTAssertTrue(members.allSatisfy(\.verified))

        try await bob.vault.sync()
        let bobsVaults = try await bob.vault.listVaults()
        XCTAssertEqual(bobsVaults.map(\.name), ["Personal", "Family recipes"])
        guard case let .login(details) = try await bob.vault.getItem(id: pasta.id).details else { return XCTFail("a login") }
        XCTAssertEqual(details.password, "al-dente")

        try await alice.vault.removeMember(vaultId: shared.id, accountId: lookup.accountId)
        try await bob.vault.sync()
        let afterRemoval = try await bob.vault.listVaults()
        XCTAssertEqual(afterRemoval.count, 1)
    }

    func testExportAndImport() async throws {
        let phone = try Phone(email: unique("lovelace"))
        try await phone.signUp()
        let personal = try await phone.personalVault()
        try await phone.vault.saveItem(draft: login("GitHub", vault: personal, username: "ada", password: "hunter2"))
        try await phone.vault.saveItem(draft: login("Forum", vault: personal, username: "ada", password: "hunter2"))

        let json = try await phone.vault.exportVault(format: .json, password: nil, masterPassword: Self.password)
        XCTAssertTrue(json.hasSuffix(".json"))
        let encrypted = try await phone.vault.exportVault(format: .encrypted, password: "export pass", masterPassword: nil)
        let report = try await phone.vault.healthReport()
        XCTAssertEqual(report.reused.count, 1)

        let other = try Phone(email: unique("babbage"))
        try await other.signUp()
        let imported = try await other.vault.importFile(source: .octaPass, path: json, password: nil, keyFilePath: nil)
        XCTAssertEqual(imported.imported, 2)
        let restored = try await other.vault.importFile(source: .octaPass, path: encrypted, password: "export pass", keyFilePath: nil)
        // The same items again, from the encrypted export: found by id, so nothing is copied.
        XCTAssertEqual(restored.imported, 0)
        XCTAssertEqual(restored.imported + restored.updated + restored.unchanged + restored.skipped, 2)
        let otherTitles = try await other.titles()
        XCTAssertEqual(otherTitles, ["Forum", "GitHub"])
    }
}
