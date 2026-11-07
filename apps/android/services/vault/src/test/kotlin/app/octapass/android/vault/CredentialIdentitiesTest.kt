package app.octap.android.vault

import org.json.JSONArray
import org.junit.Assert.assertEquals
import org.junit.Test

class CredentialIdentitiesTest {
    @Test
    fun readsWhatTheVaultSends() {
        // The shape crates/native/src/mobile.rs sends to setCredentialIdentities.
        val identities = JSONArray(
            """
            [
              { "kind": "password", "itemId": "1", "url": "androidapp://com.example", "user": "ada" },
              { "kind": "passkey", "itemId": "2", "rpId": "example.com", "userName": "ada",
                "credentialId": "AQID", "userHandle": "BAUG" },
              { "kind": "oneTimeCode", "itemId": "3", "url": "https://example.com", "label": "Example" },
              { "kind": "password", "itemId": "4" }
            ]
            """.trimIndent(),
        )
        assertEquals(
            listOf(
                CredentialIdentity.Password("1", "androidapp://com.example", "ada"),
                CredentialIdentity.Passkey("2", "example.com", "ada", "AQID", "BAUG"),
            ),
            CredentialIdentities.parse(identities),
        )
    }
}
