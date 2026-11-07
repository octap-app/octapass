package app.octap.vault

import java.io.File
import java.nio.file.Files
import java.util.UUID
import kotlinx.coroutines.runBlocking
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** The Keystore and the device lock, in memory, as the app's Keystore code would answer. */
class TestPlatform : NativePlatform {
    private val secrets = mutableMapOf<String, String>()
    private val deviceSecrets = mutableMapOf<String, ByteArray>()
    private val stayUnlockedKeys = mutableMapOf<String, ByteArray>()

    /** The phone has a screen lock (a passcode). */
    @Volatile var lockAvailable = true

    @Synchronized override fun secret(name: String): String? = secrets[name]
    @Synchronized override fun setSecret(name: String, value: String) { secrets[name] = value }
    @Synchronized override fun deleteSecret(name: String) { secrets.remove(name) }
    override fun deviceLock() = DeviceLock(available = lockAvailable, label = "Fingerprint")
    @Synchronized override fun storeDeviceSecret(name: String, secret: ByteArray) { deviceSecrets[name] = secret }

    @Synchronized override fun deviceSecret(name: String, reason: String): ByteArray =
        deviceSecrets[name] ?: throw VaultException.Failed(ErrorCode.DEVICE_UNLOCK_FAILED, "no secret")

    @Synchronized override fun deleteDeviceSecret(name: String) { deviceSecrets.remove(name) }
    override fun verifyUser(reason: String) { throw VaultException.Failed(ErrorCode.DEVICE_UNLOCK_UNSUPPORTED, "not here") }
    @Synchronized override fun storeStayUnlockedKey(name: String, key: ByteArray) { stayUnlockedKeys[name] = key.copyOf() }
    @Synchronized override fun stayUnlockedKey(name: String): ByteArray? = stayUnlockedKeys[name]?.copyOf()
    @Synchronized override fun deleteStayUnlockedKey(name: String) { stayUnlockedKeys.remove(name) }
    override fun chipAvailable() = false
    override fun createChipKey(name: String): ChipKey? = null
    override fun chipSecret(name: String, context: ByteArray) = ByteArray(0)
    override fun deleteChipKey(name: String) {}
    override fun lowMemory() = true
    override fun backupFolderFiles(folder: String) = emptyList<String>()
    override fun writeBackupFile(folder: String, name: String, source: String) {}
    override fun deleteBackupFile(folder: String, name: String) {}
    override fun setCredentialIdentities(identities: List<CredentialIdentity>) {}
}

class TestObserver : VaultObserver {
    val sessions = mutableListOf<SessionSnapshot>()

    @Synchronized override fun sessionChanged(snapshot: SessionSnapshot) { sessions.add(snapshot) }
    override fun itemsChanged() {}
    override fun syncChanged(state: SyncState) {}
    override fun sharingChanged() {}
}

/** One phone: its own app storage and Keystore. Pass another's to start the app again on it. */
class Phone(
    val email: String,
    val directory: File = Files.createTempDirectory("octapass").toFile(),
    val platform: TestPlatform = TestPlatform(),
) {
    val observer = TestObserver()
    val vault = OctaPassVault(
        VaultConfig(
            dataDir = File(directory, "vault").path,
            tempDir = File(directory, "tmp").path,
            deviceName = "Test Android",
            platform = DevicePlatform.ANDROID,
            pwnedPasswordsUrl = SERVER,
            webVaultUrl = "https://vault.octap.app",
            defaultServerUrl = "https://vault.octap.app",
        ),
        platform,
        observer,
    )

    /** Signs up on the development server, which hands back the email code. */
    suspend fun signUp(): RecoveryKit {
        val started = vault.startSignup(SERVER, email, PASSWORD)
        return vault.finishSignup(started.signupId, assertNotNull(started.devVerificationCode))
    }

    suspend fun personalVault(): String = vault.listVaults().first { it.vaultType == VaultType.PERSONAL }.id

    suspend fun titles(filter: ItemFilter = ItemFilter(null, null, null, false, false, false)): List<String> =
        vault.listItems(filter).map { it.title }.sorted()
}

val SERVER: String = System.getenv("OCTAPASS_TEST_SERVER") ?: "http://127.0.0.1:8080"
const val PASSWORD = "correct horse battery staple"

fun unique(name: String) = "$name-${UUID.randomUUID().toString().take(8)}@example.com"

fun login(title: String, vault: String, username: String, password: String): ItemDraft =
    newItemDraft(ItemType.Login, vault).copy(
        title = title,
        urls = listOf("https://${title.lowercase()}.example"),
        details = ItemDetails.Login(
            LoginDetails(username, password, null, null, emptyList(), null, emptyList(), emptyList()),
        ),
    )

inline fun <reified T> code(noinline call: suspend () -> T): ErrorCode {
    val error = assertFailsWith<VaultException.Failed> { runBlocking { call() } }
    return error.code
}

class VaultTest {
    private val phones = mutableListOf<Phone>()

    private fun phone(email: String) = Phone(email).also { phones.add(it) }

    @AfterTest
    fun cleanUp() {
        phones.forEach { it.directory.deleteRecursively() }
    }

    @Test
    fun signUpSignInWithTwoStep() = runBlocking {
        val phone = phone(unique("ada"))
        assertEquals(SessionStatus.SIGNED_OUT, phone.vault.snapshot().status)
        val kit = phone.signUp()
        assertTrue(kit.secretKey.startsWith("OP1-"))
        assertEquals(SessionStatus.UNLOCKED, phone.vault.snapshot().status)

        phone.vault.lock()
        assertEquals(ErrorCode.INVALID_CREDENTIALS, code { phone.vault.unlock("wrong") })
        phone.vault.unlock(PASSWORD)
        phone.vault.enableDeviceUnlock()
        phone.vault.lock()
        phone.vault.unlockWithDevice()
        assertEquals(SessionStatus.UNLOCKED, phone.vault.snapshot().status)

        val setup = phone.vault.startTotpSetup(PASSWORD)
        val recoveryCodes = assertNotNull(phone.vault.confirmTotpSetup(totpCode(setup.secret, null).code))

        val tablet = phone(phone.email)
        val result = tablet.vault.signIn(SERVER, phone.email, PASSWORD, kit.secretKey)
        val required = assertIs<SignInResult.TwoStepRequired>(result)
        assertEquals(listOf(TwoStepMethod.TOTP, TwoStepMethod.RECOVERY_CODE), required.methods)
        assertEquals(ErrorCode.INVALID_TWO_STEP_CODE, code { tablet.vault.finishTwoStep(TwoStepProof.Totp("000000")) })
        tablet.vault.finishTwoStep(TwoStepProof.RecoveryCode(recoveryCodes.first()))
        assertEquals(SessionStatus.UNLOCKED, tablet.vault.snapshot().status)
        assertEquals(2, tablet.vault.listDevices().size)
        assertTrue(tablet.vault.securityLog().any { it.eventType == "two-step-enabled" })

        tablet.vault.signOut()
        assertEquals(SessionStatus.SIGNED_OUT, tablet.vault.snapshot().status)
        phone.vault.deleteAccount(phone.email, PASSWORD)
        assertEquals(SessionStatus.SIGNED_OUT, phone.vault.snapshot().status)
    }

    @Test
    fun sshKeysAndEnvironments() = runBlocking {
        val phone = phone(unique("linus"))
        phone.signUp()
        val personal = phone.personalVault()

        val made = phone.vault.generateSshKey(SshKeyKind.ED25519, "me@phone")
        val draft = newItemDraft(ItemType.SshKey, personal)
        val key = phone.vault.saveItem(draft.copy(details = ItemDetails.SshKey(withSshKey((draft.details as ItemDetails.SshKey).key, made, null))))
        assertEquals("me@phone", key.title)
        val details = (key.details as ItemDetails.SshKey).key
        assertEquals("Ed25519", sshKeyTypeLabel(details))
        assertTrue(authorizedKeysLine(details).endsWith(" me@phone"))

        val merged = mergeDotenv(emptyList(), "API_KEY=abc\nDEBUG=1\n")
        assertEquals(2u, merged.count)
        val environment = newItemDraft(ItemType.Environment, personal)
        val saved = phone.vault.saveItem(environment.copy(title = "Shop", details = ItemDetails.Environment(EnvironmentDetails("shop-api", null, "production", merged.variables, null))))
        assertEquals("shop-api · production", saved.subtitle)
        assertEquals("API_KEY=abc\nDEBUG=1\n", environmentDotenv((saved.details as ItemDetails.Environment).environment))
        assertTrue(isProductionStage("production"))
    }

    @Test
    fun itemsOfEveryTypeAndAnAttachment() = runBlocking {
        val phone = phone(unique("grace"))
        phone.signUp()
        val personal = phone.personalVault()

        val github = phone.vault.saveItem(login("GitHub", personal, "grace", "hunter2"))
        assertEquals("grace", github.subtitle)
        val wifi = phone.vault.saveItem(assertNotNull(scannedDraft("WIFI:T:WPA;S:Home;P:wifi-pass;;", personal)))
        assertEquals("Home", wifi.wifi?.ssid)
        assertEquals(listOf("wifi", "password"), qrChoices(wifi).map { it.id })
        val bank = phone.vault.saveItem(
            newItemDraft(ItemType.BankAccount, personal).copy(
                title = "Savings",
                details = ItemDetails.Structured(
                    ItemType.BankAccount,
                    StructuredDetails(listOf(FieldValue("bankName", "Example Bank"), FieldValue("accountHolder", "Grace"), FieldValue("iban", "DE89 3704 0044 0532 0130 00"), FieldValue("pin", "0000")), emptyList(), emptyList(), null, null, null, emptyList(), emptyList()),
                ),
            ),
        )
        assertEquals("Example Bank", bank.subtitle)
        assertEquals(listOf("payment", "iban"), qrChoices(bank).map { it.id })
        assertTrue(qrChoices(bank).none { it.text.contains("0000") })
        assertEquals(listOf("bankName", "accountHolder", "accountType"), fieldSpecs(ItemType.BankAccount).take(3).map { it.key })
        val note = phone.vault.saveItem(
            newItemDraft(ItemType.SecureNote, personal).copy(title = "Ideas", details = ItemDetails.SecureNote(SecureNoteDetails("Write more tests"))),
        )
        val card = phone.vault.saveItem(
            newItemDraft(ItemType.Card, personal).copy(
                title = "Visa",
                details = ItemDetails.Card(CardDetails("Grace", "4111 1111 1111 1111", "01/30", "123", null, null, null)),
            ),
        )
        assertEquals("Visa ending 1111", card.subtitle)
        phone.vault.saveItem(
            newItemDraft(ItemType.Identity, personal).copy(
                title = "Me",
                details = ItemDetails.Identity(IdentityDetails("Grace", "Hopper", "grace@example.com", null, null, null, null)),
            ),
        )
        val lease = phone.vault.saveItem(
            newItemDraft(ItemType.Document, personal).copy(title = "Lease", details = ItemDetails.Document(DocumentDetails("signed"))),
        )
        val invalid = newItemDraft(ItemType.Login, personal).copy(title = " ")
        assertEquals(listOf("validation.titleRequired"), validateDraft(invalid).map { it.messageKey })
        assertEquals(ErrorCode.INVALID_INPUT, code { phone.vault.saveItem(invalid) })

        val details = (github.details as ItemDetails.Login).login
        val edited = phone.vault.saveItem(itemDraft(github).copy(details = ItemDetails.Login(details.copy(password = "new-password"))))
        assertEquals("hunter2", (edited.details as ItemDetails.Login).login.passwordHistory.first().password)
        assertTrue(phone.vault.setFavorite(github.id, true).favorite)

        assertEquals(listOf("GitHub", "Home", "Ideas", "Lease", "Me", "Savings", "Visa"), phone.titles())
        val sections = phone.vault.arrangeItems(ItemFilter(null, null, null, false, false, false), ListSort.NAME, ListGrouping.TYPE)
        assertEquals(listOf("login", "card", "identity", "secureNote", "wifi", "document", "bankAccount"), sections.map { it.key })
        assertEquals(listOf("Me"), phone.titles(ItemFilter(null, null, "hopper", false, false, false)))

        phone.vault.deleteItem(note.id)
        assertEquals(listOf("Ideas"), phone.titles(ItemFilter(null, null, null, true, false, false)))
        phone.vault.restoreItem(note.id)

        val picked = File(phone.directory, "lease.pdf").apply { writeText("%PDF-1.7 lease") }
        val withFile = phone.vault.addAttachment(lease.id, picked.path, "lease.pdf", "application/pdf")
        val file = withFile.attachments.single()
        val opened = phone.vault.openAttachment(lease.id, file.id)
        assertEquals("%PDF-1.7 lease", File(opened).readText())
        phone.vault.closeAttachment(opened)
        assertFalse(File(opened).exists())
        phone.vault.sync()
        assertEquals(0u, phone.vault.syncState().pendingFiles)
        assertTrue(phone.vault.removeAttachment(lease.id, file.id).attachments.isEmpty())
    }

    @Test
    fun sharingAVaultBetweenTwoAccounts() = runBlocking {
        val alice = phone(unique("alice"))
        val bob = phone(unique("bob"))
        alice.signUp()
        bob.signUp()

        val lookup = alice.vault.lookupAccount(bob.email)
        assertEquals(bob.vault.myFingerprint(), lookup.fingerprint)
        alice.vault.markVerified(lookup)
        val shared = alice.vault.createVault("Family recipes")
        alice.vault.addMember(shared.id, lookup, VaultRole.WRITE)
        val pasta = alice.vault.saveItem(login("Pasta", shared.id, "chef", "al-dente"))
        assertTrue(alice.vault.listMembers(shared.id).all { it.verified })

        bob.vault.sync()
        assertEquals(listOf("Personal", "Family recipes"), bob.vault.listVaults().map { it.name })
        assertEquals("al-dente", (bob.vault.getItem(pasta.id).details as ItemDetails.Login).login.password)

        alice.vault.removeMember(shared.id, lookup.accountId)
        bob.vault.sync()
        assertEquals(1, bob.vault.listVaults().size)
    }

    @Test
    fun exportAndImport() = runBlocking {
        val phone = phone(unique("lovelace"))
        phone.signUp()
        val personal = phone.personalVault()
        phone.vault.saveItem(login("GitHub", personal, "ada", "hunter2"))
        phone.vault.saveItem(login("Forum", personal, "ada", "hunter2"))

        val json = phone.vault.exportVault(ExportFormat.JSON, null, PASSWORD)
        assertTrue(json.endsWith(".json"))
        val encrypted = phone.vault.exportVault(ExportFormat.ENCRYPTED, "export pass", null)
        assertEquals(1, phone.vault.healthReport().reused.size)

        val other = phone(unique("babbage"))
        other.signUp()
        assertEquals(2u, other.vault.importFile(ImportSource.OCTA_PASS, json, null, null).imported)
        // The same items again, from the encrypted export: found by id, so nothing is copied.
        val again = other.vault.importFile(ImportSource.OCTA_PASS, encrypted, "export pass", null)
        assertEquals(0u, again.imported)
        assertEquals(2u, again.imported + again.updated + again.unchanged + again.skipped)
        assertEquals(listOf("Forum", "GitHub"), other.titles())
    }
}
