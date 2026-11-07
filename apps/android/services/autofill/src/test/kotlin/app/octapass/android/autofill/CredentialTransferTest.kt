package app.octap.android.autofill

import androidx.credentials.providerevents.exception.ImportCredentialsCancellationException
import androidx.credentials.providerevents.exception.ImportCredentialsInvalidJsonException
import androidx.credentials.providerevents.exception.ImportCredentialsNoExportOptionException
import androidx.credentials.providerevents.exception.ImportCredentialsUnknownCallerException
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class CredentialTransferTest {
    @Test
    fun anEntryKeepsItsIdForTheSameAccount() {
        val (id, stored) = ExportEntries.entryFor(null, "a1") { "secret-1" }
        assertEquals("secret-1", id)
        assertEquals("a1", JSONObject(stored!!).getString("tag"))
        val (again, nothingNew) = ExportEntries.entryFor(stored, "a1") { error("no new id for the same account") }
        assertEquals("secret-1", again)
        assertNull(nothingNew)
    }

    @Test
    fun anotherAccountGetsANewId() {
        val (_, stored) = ExportEntries.entryFor(null, "a1") { "secret-1" }
        val (id, newStored) = ExportEntries.entryFor(stored, "b2") { "secret-2" }
        assertEquals("secret-2", id)
        assertEquals("b2", JSONObject(newStored!!).getString("tag"))
        assertEquals("secret-2", ExportEntries.entryFor("not json", "b2") { "secret-2" }.first)
    }

    @Test
    fun onlyTheCurrentAccountsEntryIsAnswered() {
        val (_, stored) = ExportEntries.entryFor(null, "a1") { "secret-1" }
        assertTrue(ExportEntries.matches(stored, "a1", "secret-1"))
        assertFalse(ExportEntries.matches(stored, "a1", "secret-2"))
        // Signed in to another account since the entry was listed.
        assertFalse(ExportEntries.matches(stored, "b2", "secret-1"))
        assertFalse(ExportEntries.matches(null, "a1", ""))
        assertFalse(ExportEntries.matches("{}", "", ""))
    }

    @Test
    fun octaPassAsksForWhatItCanImportAndOffersWhatItExports() {
        assertTrue(CredentialTransfer.IMPORTS.containsAll(CredentialTransfer.EXPORTS))
        assertTrue(CredentialTransfer.EXPORTS.containsAll(setOf("basic-auth", "passkey", "totp", "note", "credit-card", "address", "wifi")))
        // Files and links to other items can't come across.
        assertFalse("file" in CredentialTransfer.IMPORTS)
        assertFalse("item-reference" in CredentialTransfer.IMPORTS)
    }

    @Test
    fun backingOutIsNotAnError() {
        assertTrue(TransferErrors.isNothing(ImportCredentialsCancellationException().type))
        assertTrue(TransferErrors.isNothing(ImportCredentialsNoExportOptionException().type))
        assertFalse(TransferErrors.isNothing(ImportCredentialsUnknownCallerException().type))
        assertTrue(TransferErrors.isInvalid(ImportCredentialsInvalidJsonException().type))
        assertFalse(TransferErrors.isInvalid(ImportCredentialsCancellationException().type))
    }
}
