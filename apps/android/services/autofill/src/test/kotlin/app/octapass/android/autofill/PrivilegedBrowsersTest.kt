package app.octap.android.autofill

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class PrivilegedBrowsersTest {
    @Test
    fun theShippedListHasTheMainBrowsersWithTheirCertificates() {
        val list = PrivilegedBrowsers.parse(File("src/main/res/raw/privileged_browsers.json").readText())
        for (browser in listOf("com.android.chrome", "org.mozilla.firefox", "com.microsoft.emmx", "com.brave.browser", "com.sec.android.app.sbrowser")) {
            assertTrue(browser, list[browser].orEmpty().isNotEmpty())
        }
        assertTrue(list.getValue("com.android.chrome").all { it.matches(Regex("([0-9A-F]{2}:){31}[0-9A-F]{2}")) })
    }

    @Test
    fun fingerprintsAreUppercaseHexWithColons() {
        assertEquals(
            "E3:B0:C4:42:98:FC:1C:14:9A:FB:F4:C8:99:6F:B9:24:27:AE:41:E4:64:9B:93:4C:A4:95:99:1B:78:52:B8:55",
            PrivilegedBrowsers.fingerprint(ByteArray(0)),
        )
    }
}
