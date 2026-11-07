package app.octap.wear

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class WatchCodesTest {
    /** The bundle the Rust tests pin: issued at this moment, with a 30-second and a 60-second item. */
    private val now = 1_700_000_012_345L

    private fun bundle(): WatchBundle {
        val text = File("../../../crates/octapass-mobile/tests/fixtures/watch-bundle.json").readText()
        return (WatchPayload.decode(text) as WatchPayload.Bundle).bundle
    }

    private fun entry(period: Int = 30, startMs: Long = 30_000, codes: List<String> = listOf("111111", "222222")): String {
        val list = codes.joinToString(",") { "\"$it\"" }
        return """{"id":"a","title":"T","favorite":false,"period":$period,"digits":6,"startMs":$startMs,"codes":[$list]}"""
    }

    private fun payload(issued: Long = 30_000, expires: Long = 60_000, entries: List<String>): WatchPayload =
        WatchPayload.decode("""{"v":1,"issuedAtMs":$issued,"expiresAtMs":$expires,"entries":[${entries.joinToString(",")}]}""")!!

    @Test
    fun readsWhatTheCoreWrites() {
        val bundle = bundle()
        assertEquals(now, bundle.issuedAtMs)
        assertEquals(now + 900_000, bundle.expiresAtMs)
        assertEquals(listOf("GitHub", "بنك الأمل"), bundle.entries.map { it.title })
        assertEquals(listOf(30L, 60L), bundle.entries.map { it.period })
        assertEquals(listOf(6, 8), bundle.entries.map { it.digits })
        assertTrue(bundle.entries[0].favorite)
        assertEquals(32, bundle.entries[0].id.length)
    }

    @Test
    fun picksTheCodeForTheMoment() {
        val entry = bundle().entries[0]
        assertEquals(entry.codes[0], entry.codeAt(entry.startMs)?.text)
        assertEquals(entry.codes[0], entry.codeAt(entry.startMs + 29_999)?.text)
        assertEquals(entry.codes[1], entry.codeAt(entry.startMs + 30_000)?.text)
        val last = entry.startMs + 30_000L * (entry.codes.size - 1)
        assertEquals(entry.codes.last(), entry.codeAt(last)?.text)
        assertNull("past the last code", entry.codeAt(last + 30_000))
        assertNull("before the first code", entry.codeAt(entry.startMs - 1))
    }

    @Test
    fun countdown() {
        val entry = bundle().entries[0]
        val start = entry.codeAt(entry.startMs)!!
        assertEquals(30, start.remainingSeconds)
        assertEquals(1f, start.fraction, 0f)
        val end = entry.codeAt(entry.startMs + 29_999)!!
        assertEquals(1, end.remainingSeconds)
        assertTrue(end.fraction < 0.01f)
    }

    @Test
    fun display() {
        fun display(text: String) = WatchCode(text, 1, 1).display
        assertEquals("123 456", display("123456"))
        assertEquals("1234 5678", display("12345678"))
        assertEquals("123 4567", display("1234567"))
        assertEquals("2BCDF", display("2BCDF"))
    }

    @Test
    fun expiresAtItsEndAndNeverLaterThanFifteenMinutes() {
        val bundle = bundle()
        val codes = WatchCodes().applying(WatchPayload.Bundle(bundle))
        assertEquals(2, codes.rows(bundle.expiresAtMs - 1).size)
        assertTrue(codes.rows(bundle.expiresAtMs).isEmpty())

        val long = WatchBundle(0, 3_600_000, bundle.entries)
        assertFalse(long.isExpired(899_999))
        assertTrue(long.isExpired(900_000))
    }

    @Test
    fun forgettingExpiredCodes() {
        val codes = WatchCodes().applying(payload(entries = listOf(entry())))
        assertEquals(1, codes.forgettingExpired(59_999).rows(59_999).size)
        val forgotten = codes.forgettingExpired(60_000)
        assertEquals(WatchCodes().applying(WatchPayload.Clear(30_000)), forgotten)
        assertTrue("gone, even if the clock is set back", forgotten.rows(30_000).isEmpty())
    }

    @Test
    fun aClearWins() {
        assertEquals(WatchPayload.Clear(40_000), WatchPayload.decode("""{"v":1,"clear":true,"issuedAtMs":40000}"""))
        val cleared = WatchCodes().applying(payload(issued = 30_000, entries = listOf(entry()))).applying(WatchPayload.Clear(40_000))
        assertTrue(cleared.rows(45_000).isEmpty())
        val late = cleared.applying(payload(issued = 35_000, entries = listOf(entry())))
        assertTrue("a late bundle stays cleared", late.rows(45_000).isEmpty())
        val newer = late.applying(payload(issued = 50_000, expires = 80_000, entries = listOf(entry())))
        assertEquals("a newer one is shown", 1, newer.rows(55_000).size)
    }

    @Test
    fun badPayloadsAreRefused() {
        assertNull(WatchPayload.decode(""))
        assertNull(WatchPayload.decode("not json"))
        assertNull(WatchPayload.decode("""{"v":2,"issuedAtMs":1,"expiresAtMs":2,"entries":[]}"""))
        assertNull(WatchPayload.decode("""{"v":1,"issuedAtMs":1}"""))
        val bundle = (payload(entries = listOf(entry(period = 0), entry(codes = emptyList()), entry())) as WatchPayload.Bundle).bundle
        assertEquals("entries that make no sense are left out", 1, bundle.entries.size)
    }

    @Test
    fun anEmptyVaultIsToldApartFromNoAnswer() {
        val none = WatchCodes()
        assertFalse(none.isEmptyVault(30_000))
        val empty = none.applying(payload(entries = emptyList()))
        assertTrue(empty.isEmptyVault(30_000))
        assertFalse(empty.isEmptyVault(60_000))
    }
}
