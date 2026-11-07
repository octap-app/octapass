package app.octap.android.vault

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class AutofillVaultTest {
    @Test
    fun theExporterIsTheServersHost() {
        assertEquals("octap.app", AutofillVault.exporterId("https://octap.app"))
        assertEquals("vault.example.org", AutofillVault.exporterId("https://vault.example.org:8443/api/"))
        assertEquals("localhost", AutofillVault.exporterId("http://localhost:8090"))
    }

    @Test
    fun theAddWebsiteOfferNamesThePageAsTheUserKnowsIt() {
        assertEquals("login.example.com", AutofillVault.displayHost("https://login.example.com/sign-in?next=/"))
        assertEquals("example.com", AutofillVault.displayHost("https://www.example.com"))
        assertEquals("bücher.example", AutofillVault.displayHost("https://xn--bcher-kva.example/"))
        assertEquals("shop.example.com", AutofillVault.displayHost("http://SHOP.example.com:8080"))
        assertNull(AutofillVault.displayHost("androidapp://com.example.app"))
        assertNull(AutofillVault.displayHost("not a url"))
    }
}
