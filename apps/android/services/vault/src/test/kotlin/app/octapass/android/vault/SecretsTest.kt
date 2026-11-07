package app.octap.android.vault

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import javax.crypto.AEADBadTagException
import javax.crypto.KeyGenerator

class SecretsTest {
    private val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()

    @Test
    fun sealedValuesOpenUnderTheirOwnName() {
        val sealed = Secrets.seal(key, "secretKey.a", "A3-ABCDEF".toByteArray())
        assertArrayEquals("A3-ABCDEF".toByteArray(), Secrets.open(key, "secretKey.a", sealed))
    }

    @Test
    fun aValueMovedToAnotherNameDoesNotOpen() {
        val sealed = Secrets.seal(key, "secretKey.a", "A3-ABCDEF".toByteArray())
        assertThrows(AEADBadTagException::class.java) { Secrets.open(key, "refreshToken.a", sealed) }
    }

    @Test
    fun everySealUsesAFreshNonce() {
        val first = Secrets.seal(key, "n", byteArrayOf(1, 2, 3))
        val second = Secrets.seal(key, "n", byteArrayOf(1, 2, 3))
        assertNotEquals(first.toList(), second.toList())
    }
}
