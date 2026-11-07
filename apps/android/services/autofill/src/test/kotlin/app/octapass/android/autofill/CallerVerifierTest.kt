package app.octap.android.autofill

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CallerVerifierTest {
    private val fingerprint = "AB:CD:EF:01"

    private fun links(relation: String = "delegate_permission/common.get_login_creds", packageName: String = "com.example.app", sha: String = fingerprint) =
        """
        [{
          "relation": ["$relation"],
          "target": { "namespace": "android_app", "package_name": "$packageName", "sha256_cert_fingerprints": ["$sha"] }
        }]
        """.trimIndent()

    @Test
    fun assetLinksMustNameThePackageAndCertificate() {
        assertTrue(AssetLinks.allows(links(), "com.example.app", listOf(fingerprint)))
        assertTrue(AssetLinks.allows(links(relation = "delegate_permission/common.handle_all_urls"), "com.example.app", listOf("ab:cd:ef:01")))
        assertFalse(AssetLinks.allows(links(), "com.evil.app", listOf(fingerprint)))
        assertFalse(AssetLinks.allows(links(), "com.example.app", listOf("00:00")))
        assertFalse(AssetLinks.allows(links(relation = "delegate_permission/common.use_as_origin"), "com.example.app", listOf(fingerprint)))
        assertFalse(AssetLinks.allows("{ not json", "com.example.app", listOf(fingerprint)))
    }

    @Test
    fun anRpIdIsTheOriginsHostOrADomainAboveIt() {
        assertTrue(Origins.rpIdMatches("example.com", "https://example.com"))
        assertTrue(Origins.rpIdMatches("example.com", "https://login.example.com:8443"))
        assertFalse(Origins.rpIdMatches("example.com", "https://example.com.evil.io"))
        assertFalse(Origins.rpIdMatches("example.com", "https://notexample.com"))
        assertFalse(Origins.rpIdMatches("example.com", "http://example.com"))
        assertTrue(Origins.rpIdMatches("localhost", "http://localhost:8080"))
    }

    @Test
    fun appOriginsAreTheCertificateHash() {
        // SHA-256 of an empty certificate, base64url without padding.
        assertEquals("android:apk-key-hash:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU", Origins.app(ByteArray(0)))
    }

    @Test
    fun clientDataNamesTheApp() {
        val json = JSONObject(ClientDataJson.build("webauthn.get", byteArrayOf(1, 2, 3), "android:apk-key-hash:x", "com.example.app"))
        assertEquals("webauthn.get", json.getString("type"))
        assertEquals("AQID", json.getString("challenge"))
        assertEquals("android:apk-key-hash:x", json.getString("origin"))
        assertEquals("com.example.app", json.getString("androidPackageName"))
    }
}
