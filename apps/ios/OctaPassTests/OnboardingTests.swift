import AuthenticationServices
import OctaPassKeychain
import OctaPassResources
import OctaPassVault
import XCTest
@testable import OctaPass

final class OnboardingTests: XCTestCase {
    override func setUp() {
        L10n.setLanguage("en")
    }

    override func tearDown() {
        L10n.setLanguage(nil)
    }

    func testErrorsSayWhatTheWebVaultSays() {
        let error = VaultError.Failed(code: .invalidCredentials, reason: "401")
        XCTAssertEqual(error.message, L10n.errors.invalidCredentials)
        XCTAssertTrue(error.isVault(.invalidCredentials))
        // A code the catalog has no message for, and errors that aren't the vault's.
        XCTAssertEqual(VaultError.Failed(code: .invalidInput, reason: "").message, L10n.errors.unexpected)
        XCTAssertEqual(CocoaError(.fileNoSuchFile).message, L10n.errors.unexpected)
    }

    func testArabicMessagesComeFromTheSameCatalog() {
        L10n.setLanguage("ar")
        XCTAssertNotEqual(VaultError.Failed(code: .invalidCredentials, reason: "").message, "")
        XCTAssertNotEqual(L10n.signIn.title, "Sign in")
    }

    func testDeviceLockNames() {
        XCTAssertEqual(DeviceLockName.name("Face ID"), "Face ID")
        XCTAssertEqual(DeviceLockName.name("Passcode"), L10n.phone.native.passcode)
        XCTAssertEqual(DeviceLockName.offer("Touch ID"), "Touch ID")
        XCTAssertEqual(DeviceLockName.offer("Passcode"), L10n.unlockOffer.passcode)
        XCTAssertEqual(DeviceLockName.icon("Face ID"), "faceid")
    }

    func testServerChoice() {
        XCTAssertEqual(ServerChoice().serverUrl(hosted: "https://api.example"), "https://api.example")
        XCTAssertEqual(ServerChoice(selfHosted: true, url: " https://vault.example.com ").serverUrl(hosted: "x"), "https://vault.example.com")
    }

    func testCredentialIdentitiesForTheSystem() throws {
        let password = try XCTUnwrap(VaultPlatform.system(.password(itemId: "i", url: "https://a.example", user: "ada")))
        XCTAssertEqual((password as? ASPasswordCredentialIdentity)?.user, "ada")
        XCTAssertEqual(password.recordIdentifier, "i")
        let passkey = VaultPlatform.system(.passkey(itemId: "p", rpId: "a.example", userName: "ada", credentialId: Data([1]), userHandle: Data([2])))
        XCTAssertEqual((passkey as? ASPasskeyCredentialIdentity)?.relyingPartyIdentifier, "a.example")

        // Saved as typed: a URL the system can read a host from. Not a website: not registered.
        let bare = VaultPlatform.system(.password(itemId: "i", url: " github.com/login ", user: "ada"))
        XCTAssertEqual(bare?.serviceIdentifier.identifier, "https://github.com/login")
        XCTAssertEqual(bare?.serviceIdentifier.type, .URL)
        XCTAssertEqual(VaultPlatform.website("localhost:8080"), "https://localhost:8080")
        XCTAssertEqual(VaultPlatform.website("HTTP://a.example/x"), "HTTP://a.example/x")
        XCTAssertNil(VaultPlatform.system(.password(itemId: "i", url: "androidapp://com.example", user: "ada")))
        XCTAssertNil(VaultPlatform.website(""))
    }

    func testKeychainFailuresBecomeVaultCodes() {
        // An unknown item reads as nothing, not an error; the device lock is described in English.
        let platform = VaultPlatform(keychain: .init(accessGroup: nil, service: "app.octap.tests.\(UUID())"))
        XCTAssertNil(try platform.secret(name: "missing"))
        XCTAssertFalse(platform.deviceLock().label.isEmpty)
    }

    /// The vault lives where the AutoFill extension can read it.
    func testTheAppGroupIsShared() throws {
        let group = try XCTUnwrap(SharedContainer.url(), "the App Group \(SharedContainer.appGroup) isn't available")
        XCTAssertTrue(FileManager.default.isWritableFile(atPath: group.path))
    }

    func testDates() {
        XCTAssertNotNil(Dates.parse("2026-10-24T08:00:00Z"))
        XCTAssertNotNil(Dates.parse("2024-07-12T11:46:53.312Z"))
        XCTAssertEqual(Dates.long("not a date"), "not a date")
        XCTAssertTrue(Dates.long("2026-10-24T08:00:00Z").contains("2026"))
    }

    @MainActor
    func testRecoveryKitPDFIsOnePage() throws {
        let kit = RecoveryKit(email: "ada@example.com", serverUrl: "https://vault.example.com", secretKey: "OP1-AAAAAA", recoveryCode: "AAAA-BBBB", createdAt: "2026-10-24T08:00:00Z")
        let data = try RecoveryKitPDF.data(kit)
        XCTAssertEqual(CGPDFDocument(CGDataProvider(data: data as CFData)!)?.numberOfPages, 1)
        let url = try RecoveryKitPDF.write(kit)
        XCTAssertTrue(FileManager.default.fileExists(atPath: url.path))
        RecoveryKitPDF.remove()
        XCTAssertFalse(FileManager.default.fileExists(atPath: url.path))
        XCTAssertNotNil(QRCodeImage.image(recoveryKitSetupUri(kit: kit)))
    }

    /// Replacing the Secret Key can keep the recovery code: the kit prints without one.
    @MainActor
    func testRecoveryKitPDFWithoutARecoveryCode() throws {
        let kit = NewRecoveryKit(email: "ada@example.com", serverUrl: "https://vault.example.com", secretKey: "OP1-AAAAAA", recoveryCode: nil, createdAt: "2026-10-24T08:00:00Z")
        let data = try RecoveryKitPDF.data(kit)
        XCTAssertEqual(CGPDFDocument(CGDataProvider(data: data as CFData)!)?.numberOfPages, 1)
        XCTAssertNotNil(QRCodeImage.image(kit.setupUri))
    }
}
