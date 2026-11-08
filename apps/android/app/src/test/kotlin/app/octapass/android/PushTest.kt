package app.octap.android

import app.octap.android.platform.FcmConfig
import app.octap.android.platform.PushKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class PushTest {
    @Test
    fun readsOnlyTheKindOfTheRelaysPushes() {
        assertEquals(PushKind.Sync, PushKind.of(mapOf("octapass" to "sync")))
        assertEquals(PushKind.Alert, PushKind.of(mapOf("octapass" to "alert")))
        // A kind from a newer relay still syncs; a push that isn't the relay's does nothing.
        assertEquals(PushKind.Sync, PushKind.of(mapOf("octapass" to "somethingNew")))
        assertNull(PushKind.of(emptyMap()))
        assertNull(PushKind.of(mapOf("other" to "sync")))
    }

    @Test
    fun startsFirebaseOnlyWithAllFourValues() {
        assertNull(FcmConfig.of("", "", "", ""))
        assertNull(FcmConfig.of("project", "1:2:android:3", "key", ""))
        assertNull(FcmConfig.of("project", "1:2:android:3", "  ", "2"))
        assertEquals(
            FcmConfig("project", "1:2:android:3", "key", "2"),
            FcmConfig.of(" project", "1:2:android:3", "key ", "2"),
        )
    }
}
