package app.octap.core

import java.nio.file.Files
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import kotlin.io.path.absolutePathString
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** What the app does with OkHttp, minus the network: every request goes to the in-process TestServer. */
class Loopback(private val server: TestServer) : HttpClient {
    override fun send(request: HttpRequest): HttpResponse = server.handle(request)
}

class FlowTest {
    private val email = "alice@example.com"
    private val password = "correct horse battery staple"
    private val device = DeviceInfo(name = "Pixel", platform = "android")
    private val directory = Files.createTempDirectory("octapass-ffi")

    private fun storePath(name: String) = directory.resolve(name).absolutePathString()

    private fun signedIn(result: LogInResult): SignedIn = when (result) {
        is LogInResult.SignedIn -> result.signedIn
        is LogInResult.SecondFactorRequired -> error("expected no second step")
        is LogInResult.SsoRequired -> error("expected no single sign-on step")
    }

    @Test
    fun signUpLogInFillTotpAndPasskeys() {
        val server = TestServer()
        val api = OctaPassServer("https://octapass.test", Loopback(server))
        assertEquals(1u, api.serverInfo().apiVersion)

        // Sign-up, then save a login and upload it (encrypt).
        val signup = api.startSignup(email, password)
        val secretKey = signup.secretKey()
        val laptop = signup.finish(signup.devVerificationCode()!!, device)
        val laptopStore = LocalStore.create(storePath("laptop.store"), api.baseUrl(), laptop.session)
        api.sync(laptop.tokens.accessToken, laptopStore)
        val itemId = laptop.session.saveLogin(
            laptopStore,
            LoginDraft(
                itemId = null, title = "GitHub", url = "https://github.com", username = "alice",
                password = "hunter2", totp = "JBSWY3DPEHPK3PXP",
            ),
        )
        api.uploadPending(laptop.tokens.accessToken, laptop.session, laptopStore)
        assertEquals(1uL, server.itemCount(email))

        // Log in on a new device with the Secret Key, then decrypt and fill.
        assertFailsWith<OctaPassException.LoginFailed> { api.logInTrusted(email, "wrong", secretKey, device, null) }
        val phone = signedIn(api.logInTrusted(email, password, secretKey, device, null))
        val store = LocalStore.create(storePath("phone.store"), api.baseUrl(), phone.session)
        api.sync(phone.tokens.accessToken, store)
        val session = phone.session
        val matches = session.matchLogins(store, "https://github.com/login")
        assertEquals(listOf(itemId), matches.map { it.item.itemId })
        assertEquals(MatchQuality.EXACT, matches.single().quality)
        assertTrue(session.matchLogins(store, "androidapp://com.github.android").isEmpty())
        assertEquals("hunter2", session.getItem(store, itemId).login?.password)

        val code = session.totpCode(store, itemId)
        assertEquals(6, code.code.length)
        assertEquals(30uL, code.period)

        // A passkey for an Android app: the provider built clientDataJSON with the app's origin.
        val request = passkeyCreationRequestFromJson(
            """{"rp":{"id":"example.com","name":"Example"},"user":{"id":"AQIDBA","name":"alice","displayName":"Alice"},
               "challenge":"Y2hhbGxlbmdl","pubKeyCredParams":[{"type":"public-key","alg":-7}]}""",
        )
        val created = session.createPasskey(
            store, request,
            ClientData.Json("""{"type":"webauthn.create","challenge":"Y2hhbGxlbmdl","origin":"android:apk-key-hash:abc"}"""),
        )
        val clientDataJson = """{"type":"webauthn.get","challenge":"bm9uY2U","origin":"android:apk-key-hash:abc"}"""
        val assertion = session.getPasskeyAssertion(
            store,
            passkeyAssertionRequestFromJson("""{"challenge":"bm9uY2U","rpId":"example.com"}"""),
            ClientData.Json(clientDataJson),
            created.credentialId,
        )
        assertContentEquals(byteArrayOf(1, 2, 3, 4), assertion.userHandle)
        val publicKey = Regex("\"publicKey\":\"([^\"]+)\"").find(created.responseJson)!!.groupValues[1]
        val verifier = Signature.getInstance("SHA256withECDSA").apply {
            initVerify(KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(Base64.getUrlDecoder().decode(publicKey))))
            update(assertion.authenticatorData)
            update(MessageDigest.getInstance("SHA-256").digest(clientDataJson.toByteArray()))
        }
        assertTrue(verifier.verify(assertion.signature), "a relying party accepts the assertion")

        assertFailsWith<OctaPassException.PasskeyExcluded> {
            session.createPasskey(
                store, request.copy(excludedCredentials = listOf(created.credentialId)),
                ClientData.Hash(ByteArray(32)),
            )
        }
        assertTrue(
            session.credentialIdentities(store).any { it is CredentialIdentity.Passkey && it.rpId == "example.com" },
        )
    }

    @Test
    fun twoStepSignInAndTrustedDevices() {
        val server = TestServer()
        val api = OctaPassServer("https://octapass.test", Loopback(server))
        val signup = api.startSignup(email, password)
        val secretKey = signup.secretKey()
        val laptop = signup.finish(signup.devVerificationCode()!!, device)
        val laptopTrust = laptop.tokens.trustedDeviceToken
        assertTrue(laptopTrust != null, "every sign-in trusts its device")
        server.enableTwoStep(email)

        // The old call can't finish it and says why.
        val old = assertFailsWith<OctaPassException.Server> { api.logIn(email, password, secretKey, device) }
        assertEquals("second-factor-required", old.problemType)

        val challenge = when (val result = api.logInTrusted(email, password, secretKey, device, null)) {
            is LogInResult.SecondFactorRequired -> result.secondFactor
            is LogInResult.SignedIn -> error("expected a second step")
            is LogInResult.SsoRequired -> error("expected a second step, not single sign-on")
        }
        assertEquals(listOf(SecondFactorMethod.TOTP, SecondFactorMethod.RECOVERY_CODE), challenge.methods())
        val wrong = assertFailsWith<OctaPassException.Server> { challenge.finishWithTotp("000000") }
        assertEquals("invalid-second-factor", wrong.problemType)
        val phone = challenge.finishWithTotp("654321")
        assertTrue(phone.tokens.trustedDeviceToken != null)

        // A trusted device skips the second step.
        val again = signedIn(api.logInTrusted(email, password, secretKey, device, laptopTrust))
        assertTrue(again.tokens.trustedDeviceToken != laptopTrust, "the token is replaced")
    }

    @Test
    fun theAutofillServiceUnlocksWithTheDeviceLock() {
        val api = OctaPassServer("https://octapass.test", Loopback(TestServer()))
        val signup = api.startSignup(email, password)
        val signedIn = signup.finish(signup.devVerificationCode()!!, device)
        val path = storePath("shared.store")
        val appStore = LocalStore.create(path, api.baseUrl(), signedIn.session)
        api.sync(signedIn.tokens.accessToken, appStore)
        signedIn.session.saveLogin(
            appStore,
            LoginDraft(itemId = null, title = null, url = "https://example.com", username = "alice", password = "pw", totp = null),
        )

        // The app turns device unlock on with a secret released by BiometricPrompt.
        val deviceSecret = ByteArray(32) { it.toByte() }
        appStore.enableDeviceUnlock(signedIn.session, deviceSecret)

        // The autofill service opens the same file on its own.
        LocalStore.open(path).use { serviceStore ->
            assertFailsWith<OctaPassException.DeviceUnlockFailed> { serviceStore.unlockWithDevice(ByteArray(32)) }
            val session = serviceStore.unlockWithDevice(deviceSecret)
            assertEquals(listOf("example.com"), session.listItems(serviceStore).map { it.title })
            session.lock()
            assertFailsWith<OctaPassException.Locked> { session.listItems(serviceStore) }
        }
    }

    @Test
    fun otherPartsOfASiteWaitBehindOneEntry() {
        val api = OctaPassServer("https://octapass.test", Loopback(TestServer()))
        val signup = api.startSignup(email, password)
        val signedIn = signup.finish(signup.devVerificationCode()!!, device)
        val store = LocalStore.create(storePath("parts.store"), api.baseUrl(), signedIn.session)
        api.sync(signedIn.tokens.accessToken, store)
        val session = signedIn.session
        val shop = session.saveLogin(
            store,
            LoginDraft(itemId = null, title = "Shop", url = "https://shop.example.com", username = "alice", password = "pw", totp = null),
        )

        // A sibling isn't suggested: it waits behind "Logins for other parts of example.com".
        val page = "https://login.example.com/sign-in"
        assertTrue(session.matchLogins(store, page).isEmpty())
        val other = session.otherLogins(store, page).single()
        assertEquals(shop, other.item.itemId)
        assertEquals("shop.example.com", other.host)
        assertEquals("example.com", other.site)
        assertTrue(other.canAddWebsite)

        // After the user fills it there, adding the page makes it a suggestion, once.
        val website = websiteForPage(page)!!
        assertEquals("https://login.example.com", website)
        repeat(2) {
            session.saveLogin(store, LoginDraft(itemId = shop, title = null, url = website, username = null, password = null, totp = null))
        }
        assertEquals(listOf(shop), session.matchLogins(store, page).map { it.item.itemId })
        assertTrue(session.otherLogins(store, page).isEmpty())
        assertEquals(2, session.listItems(store).single { it.itemId == shop }.urls.size)

        // Apps match only their package.
        assertEquals(null, websiteForPage("androidapp://com.example.shop"))
        assertTrue(session.otherLogins(store, "androidapp://com.example.login").isEmpty())
    }

    @Test
    fun toolsNeedNoVault() {
        val password = generatePassword(GeneratorOptions.Passphrase(words = 5u, separator = "-", capitalize = true, includeNumber = true))
        assertEquals(5, password.split("-").size)
        assertEquals("287082", totpCode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 59uL).code)
        assertFailsWith<OctaPassException.InvalidSecretKey> { normalizeSecretKey("nope") }
    }
}
