package app.octap.android

import app.octap.android.ui.vault.NearbyLogic
import app.octap.android.ui.vault.NearbyLogic.Distance
import app.octap.android.ui.vault.NearbyLogic.LocationState
import app.octap.android.ui.vault.NearbyLogic.Reading
import app.octap.android.ui.vault.NearbyLogic.Reason
import app.octap.android.ui.vault.Scope
import app.octap.vault.Here
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class NearbyLogicTest {
    @Test
    fun distancesRoundLikeTheWebVault() {
        assertEquals(Distance(10.0, false, 0), NearbyLogic.distance(0.0))
        assertEquals(Distance(10.0, false, 0), NearbyLogic.distance(3.0))
        assertEquals(Distance(870.0, false, 0), NearbyLogic.distance(868.0))
        assertEquals(Distance(990.0, false, 0), NearbyLogic.distance(994.9))
        // 996 m rounds to 1,000 m, which is shown as a kilometre, not "1,000 m".
        assertEquals(Distance(1.0, true, 1), NearbyLogic.distance(996.0))
        assertEquals(Distance(1.2, true, 1), NearbyLogic.distance(1_234.0))
        assertEquals(Distance(9.9, true, 1), NearbyLogic.distance(9_940.0))
        assertEquals(Distance(10.0, true, 0), NearbyLogic.distance(10_000.0))
        assertEquals(Distance(37.0, true, 0), NearbyLogic.distance(36_800.0))
    }

    @Test
    fun hereCarriesTheNetworkAndOneReading() {
        assertEquals(Here(emptyList(), null, null, null), NearbyLogic.here(null, null))
        assertEquals(Here(emptyList(), null, null, null), NearbyLogic.here("", null))
        assertEquals(Here(listOf("Office"), 51.5, -0.12, 20.0), NearbyLogic.here("Office", Reading(51.5, -0.12, 20.0)))
        // An accuracy of 0 means the system didn't say.
        assertNull(NearbyLogic.here(null, Reading(1.0, 2.0, 0.0)).accuracy)
        assertFalse(NearbyLogic.knowsWhere(NearbyLogic.here(null, null)))
        assertTrue(NearbyLogic.knowsWhere(NearbyLogic.here("Home", null)))
        assertTrue(NearbyLogic.knowsWhere(NearbyLogic.here(null, Reading(1.0, 2.0, null))))
    }

    @Test
    fun aPlaceIsOfferedOnlyOnceForANewItemWithTheSettingOnAndAPlaceToTell() {
        val here = NearbyLogic.here("Office", null)
        assertTrue(NearbyLogic.shouldAsk("a", fresh = true, settingOn = true, asked = emptySet(), here = here))
        assertFalse(NearbyLogic.shouldAsk("a", fresh = false, settingOn = true, asked = emptySet(), here = here))
        assertFalse(NearbyLogic.shouldAsk("a", fresh = true, settingOn = false, asked = emptySet(), here = here))
        assertFalse(NearbyLogic.shouldAsk("a", fresh = true, settingOn = true, asked = setOf("a"), here = here))
        assertFalse(NearbyLogic.shouldAsk("a", fresh = true, settingOn = true, asked = emptySet(), here = NearbyLogic.here(null, null)))
    }

    @Test
    fun saysWhyNoPlaceIsHere() {
        val nowhere = NearbyLogic.here(null, null)
        assertEquals(Reason.NO_MATCH, NearbyLogic.reason(NearbyLogic.here("Café", null), LocationState.DENIED))
        assertEquals(Reason.LOCATION_DENIED, NearbyLogic.reason(nowhere, LocationState.DENIED))
        assertEquals(Reason.LOCATION_OFF, NearbyLogic.reason(nowhere, LocationState.OFF))
        assertEquals(Reason.LOCATION_UNAVAILABLE, NearbyLogic.reason(nowhere, LocationState.UNAVAILABLE))
    }

    @Test
    fun typedCoordinatesComeInPairs() {
        assertEquals(Result.success(null), NearbyLogic.point(" ", ""))
        assertEquals(51.5 to -0.12, NearbyLogic.point("51,5", " -0.12 ").getOrNull())
        assertTrue(NearbyLogic.point("51.5", "").isFailure)
        assertTrue(NearbyLogic.point("91", "0").isFailure)
        assertTrue(NearbyLogic.point("0", "181").isFailure)
        assertTrue(NearbyLogic.point("north", "0").isFailure)
    }

    @Test
    fun nearbyIsAListOfItsOwn() {
        assertEquals("nearby", Scope.Nearby.view)
        assertEquals("nearby", Scope.Nearby.countKey)
    }
}
