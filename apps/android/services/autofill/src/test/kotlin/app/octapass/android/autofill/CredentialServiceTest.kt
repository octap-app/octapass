package app.octap.android.autofill

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class CredentialServiceTest {
    @Test
    fun cachedLoginsMatchTheAppOrTheSiteAboveAndBelow() {
        val suggested = OctaPassCredentialService.Companion::suggested
        assertTrue(suggested("androidapp://com.example", "androidapp://com.example"))
        assertFalse(suggested("androidapp://com.example", "androidapp://com.example.evil"))
        assertTrue(suggested("https://example.com/login", "https://example.com"))
        assertTrue(suggested("https://www.example.com", "https://example.com"))
        // A domain above the page, and a host below it.
        assertTrue(suggested("https://example.com", "https://login.example.com"))
        assertTrue(suggested("https://login.example.com", "https://example.com"))
        // Never another part of the domain.
        assertFalse(suggested("https://shop.example.com", "https://login.example.com"))
        assertFalse(suggested("https://example.com", "https://example.com.evil.io"))
        assertFalse(suggested("https://badexample.com", "https://example.com"))
        assertFalse(suggested("https://example.com", "androidapp://example.com"))
    }

    @Test
    fun otherPartsOfTheSiteGetOneActionNamedAfterTheDomain() {
        val otherPart = OctaPassCredentialService.Companion::otherPart
        assertEquals("example.com", otherPart("https://shop.example.com", "https://login.example.com"))
        assertEquals("example.com", otherPart("https://a.shop.example.com", "https://login.example.com"))
        assertEquals("example.co.uk", otherPart("https://shop.example.co.uk", "https://www.login.example.co.uk"))
        assertEquals("bücher.example", otherPart("https://shop.xn--bcher-kva.example", "https://login.xn--bcher-kva.example"))
        // Suggested anyway, or nothing in common but a public suffix.
        assertNull(otherPart("https://example.com", "https://login.example.com"))
        assertNull(otherPart("https://shop.example.com", "https://shop.example.com"))
        assertNull(otherPart("https://bbc.co.uk", "https://tesco.co.uk"))
        assertNull(otherPart("https://one.com", "https://two.com"))
        assertNull(otherPart("http://10.0.0.1", "http://11.0.0.1"))
        assertNull(otherPart("androidapp://com.example.shop", "androidapp://com.example.login"))
    }

    @Test
    fun readsTheRelyingPartyAndAllowedCredentials() {
        val (rpId, allowed) = OctaPassCredentialService.passkeyRequest(
            """{ "challenge": "AA", "rpId": "example.com", "allowCredentials": [{ "type": "public-key", "id": "AQID" }] }""",
        )
        assertEquals("example.com", rpId)
        assertEquals(setOf("AQID"), allowed)
        assertEquals(null to emptySet<String>(), OctaPassCredentialService.passkeyRequest("""{ "challenge": "AA" }"""))
    }
}
