package app.octap.android.platform

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import java.io.File

/**
 * The folder automatic backups go to, picked with the system's folder picker (any document
 * provider: Drive, Dropbox, a USB drive). The vault knows it by its persisted tree URI.
 */
class BackupFolder(private val context: Context) {
    private val resolver get() = context.contentResolver

    private fun tree(folder: String): Pair<Uri, String> {
        val uri = Uri.parse(folder)
        return uri to DocumentsContract.getTreeDocumentId(uri)
    }

    fun list(folder: String): List<String> {
        val (uri, parent) = tree(folder)
        val children = DocumentsContract.buildChildDocumentsUriUsingTree(uri, parent)
        val column = arrayOf(DocumentsContract.Document.COLUMN_DISPLAY_NAME)
        return resolver.query(children, column, null, null, null)?.use { rows ->
            buildList { while (rows.moveToNext()) add(rows.getString(0)) }
        }.orEmpty()
    }

    fun write(folder: String, name: String, source: String) {
        val (uri, parent) = tree(folder)
        delete(folder, name)
        val document = DocumentsContract.createDocument(
            resolver,
            DocumentsContract.buildDocumentUriUsingTree(uri, parent),
            "application/octet-stream",
            name,
        ) ?: error("the folder took no new file")
        resolver.openOutputStream(document, "wt")!!.use { output ->
            File(source).inputStream().use { it.copyTo(output) }
        }
    }

    fun delete(folder: String, name: String) {
        val (uri, parent) = tree(folder)
        val children = DocumentsContract.buildChildDocumentsUriUsingTree(uri, parent)
        val columns = arrayOf(DocumentsContract.Document.COLUMN_DOCUMENT_ID, DocumentsContract.Document.COLUMN_DISPLAY_NAME)
        val id = resolver.query(children, columns, null, null, null)?.use { rows ->
            generateSequence { rows.takeIf { it.moveToNext() } }
                .firstOrNull { it.getString(1) == name }?.getString(0)
        } ?: return
        DocumentsContract.deleteDocument(resolver, DocumentsContract.buildDocumentUriUsingTree(uri, id))
    }
}
