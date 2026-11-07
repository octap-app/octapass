package app.octap.android.platform

import android.content.Context
import android.database.Cursor
import android.database.MatrixCursor
import android.os.CancellationSignal
import android.os.Handler
import android.os.HandlerThread
import android.os.ParcelFileDescriptor
import android.os.ProxyFileDescriptorCallback
import android.os.storage.StorageManager
import android.provider.DocumentsContract
import android.provider.DocumentsContract.Document
import android.provider.DocumentsContract.Root
import android.provider.DocumentsProvider
import android.system.ErrnoException
import android.system.OsConstants
import android.util.Log
import android.webkit.MimeTypeMap
import app.octap.android.OctaPassApp
import app.octap.android.R
import app.octap.vault.SafeDrive
import app.octap.vault.SafeEntry
import app.octap.vault.VaultException
import app.octap.vault.safeRootId
import java.io.FileNotFoundException
import java.io.IOException
import java.util.Locale

/** What a document id says, and names free in a folder. No Android classes, so the JVM tests cover them. */
object SafeDocuments {
    /** `<safeItemId>:<objectId>`. */
    fun documentId(item: String, entry: String): String = "$item:$entry"

    /** The item and object of a document id, or null when it isn't one. */
    fun parse(documentId: String): Pair<String, String>? {
        val item = documentId.substringBefore(':', "")
        val entry = documentId.substringAfter(':', "")
        return if (item.isEmpty() || entry.isEmpty() || ':' in entry) null else item to entry
    }

    /**
     * [name], or `name (2).txt`, as the engine numbers names, when [taken] holds it. The engine's
     * rename replaces whatever has the name already, which a Files app never means.
     */
    fun uniqueName(name: String, taken: Set<String>): String {
        if (name !in taken) return name
        val dot = name.lastIndexOf('.').takeIf { it > 0 }
        val stem = dot?.let { name.substring(0, it) } ?: name
        val extension = dot?.let { name.substring(it) } ?: ""
        return generateSequence(2) { it + 1 }.map { "$stem ($it)$extension" }.first { it !in taken }
    }

    /** [name] with [extension] on the end, unless it's there already. */
    fun withExtension(name: String, extension: String?): String =
        if (extension.isNullOrEmpty() || name.lowercase(Locale.ROOT).endsWith(".${extension.lowercase(Locale.ROOT)}")) name else "$name.$extension"
}

/**
 * Open Safes in the system's Files app and every document picker. The roots are
 * [SafeDrives.open], so with the vault locked there are none, and this provider has nothing to
 * read with: it runs in the app's process, on the unlocked vault's drives, and holds no key. Only
 * the system's document UI can call it (`MANAGE_DOCUMENTS`), and an app reaches a file only through
 * a grant the user made in a picker, which stops working the moment the vault locks.
 *
 * File contents never reach the disk as plaintext. [openDocument] hands out a proxy descriptor
 * whose reads and writes go through [SafeFile] to the engine, chunk by chunk. So there's no
 * decrypted temporary file here, for reads or writes, and no thumbnails.
 */
class SafeDocumentsProvider : DocumentsProvider() {
    /** ContentProviders start before the Application's `onCreate`, so this comes at each call. */
    private val drives: SafeDrives? get() = (context?.applicationContext as? OctaPassApp)?.safes

    private val fileThread by lazy { HandlerThread("octapass-safe-files").apply { start() } }
    private val files by lazy { Handler(fileThread.looper) }

    /** Checking a name is free and taking it are one step: taking a name that's in use replaces it. */
    private val naming = Any()

    private val appContext: Context get() = requireNotNull(context)
    private val authority: String get() = SafeDrives.authority(appContext)

    override fun onCreate(): Boolean = true

    private class Target(val safe: OpenSafe, val entry: String) {
        val drive: SafeDrive get() = safe.drive
        val itemId: String get() = safe.item.itemId
        val documentId: String get() = SafeDocuments.documentId(itemId, entry)
    }

    /** Throws when the vault is locked, the same as for a document that doesn't exist. */
    private fun target(documentId: String): Target {
        val (item, entry) = SafeDocuments.parse(documentId) ?: throw FileNotFoundException("not a document")
        val safe = drives?.open?.value?.get(item) ?: throw FileNotFoundException("this Safe isn't open")
        return Target(safe, entry)
    }

    /** Drive errors as the framework expects them. Their reason is for logs and holds no secret. */
    private inline fun <T> reading(work: () -> T): T = try {
        work()
    } catch (error: VaultException) {
        throw FileNotFoundException(error.toString())
    }

    /** After every change to a Safe: the Files app reads the folder again, and a synced Safe syncs soon. */
    private fun notifyChildren(item: String, folder: String) {
        val uri = DocumentsContract.buildChildDocumentsUri(authority, SafeDocuments.documentId(item, folder))
        appContext.contentResolver.notifyChange(uri, null)
        drives?.syncSoon(item)
    }

    override fun queryRoots(projection: Array<String>?): Cursor {
        val cursor = MatrixCursor(projection ?: ROOT_COLUMNS)
        cursor.setNotificationUri(appContext.contentResolver, DocumentsContract.buildRootsUri(authority))
        val free = appContext.filesDir.usableSpace
        for (safe in drives?.open?.value?.values.orEmpty()) {
            cursor.newRow().apply {
                add(Root.COLUMN_ROOT_ID, safe.item.itemId)
                add(Root.COLUMN_DOCUMENT_ID, SafeDocuments.documentId(safe.item.itemId, safeRootId()))
                add(Root.COLUMN_TITLE, safe.item.name)
                add(Root.COLUMN_SUMMARY, appContext.getString(R.string.app_name))
                add(Root.COLUMN_FLAGS, Root.FLAG_LOCAL_ONLY or Root.FLAG_SUPPORTS_CREATE or Root.FLAG_SUPPORTS_IS_CHILD)
                add(Root.COLUMN_ICON, R.mipmap.ic_launcher)
                add(Root.COLUMN_AVAILABLE_BYTES, free)
            }
        }
        return cursor
    }

    private fun MatrixCursor.addEntry(item: String, entry: SafeEntry, title: String = entry.name) {
        val root = entry.id == safeRootId()
        var flags = 0
        flags = flags or if (entry.folder) Document.FLAG_DIR_SUPPORTS_CREATE else Document.FLAG_SUPPORTS_WRITE
        if (!root) flags = flags or Document.FLAG_SUPPORTS_DELETE or Document.FLAG_SUPPORTS_RENAME or Document.FLAG_SUPPORTS_MOVE
        newRow().apply {
            add(Document.COLUMN_DOCUMENT_ID, SafeDocuments.documentId(item, entry.id))
            add(Document.COLUMN_DISPLAY_NAME, title)
            add(Document.COLUMN_MIME_TYPE, mimeType(entry))
            add(Document.COLUMN_SIZE, if (entry.folder) null else entry.size.toLong())
            add(Document.COLUMN_LAST_MODIFIED, entry.modified.toLong().takeIf { it > 0 })
            add(Document.COLUMN_FLAGS, flags)
        }
    }

    private fun mimeType(entry: SafeEntry): String {
        if (entry.folder) return Document.MIME_TYPE_DIR
        val extension = entry.name.substringAfterLast('.', "").lowercase(Locale.ROOT)
        return MimeTypeMap.getSingleton().getMimeTypeFromExtension(extension) ?: "application/octet-stream"
    }

    override fun queryDocument(documentId: String, projection: Array<String>?): Cursor = reading {
        val target = target(documentId)
        MatrixCursor(projection ?: DOCUMENT_COLUMNS).apply {
            val entry = target.drive.entry(target.entry)
            // The top of a Safe has no name of its own.
            addEntry(target.itemId, entry, if (entry.id == safeRootId()) target.safe.item.name else entry.name)
        }
    }

    override fun queryChildDocuments(parentDocumentId: String, projection: Array<String>?, sortOrder: String?): Cursor = reading {
        val parent = target(parentDocumentId)
        MatrixCursor(projection ?: DOCUMENT_COLUMNS).apply {
            setNotificationUri(appContext.contentResolver, DocumentsContract.buildChildDocumentsUri(authority, parentDocumentId))
            for (entry in parent.drive.list(parent.entry)) addEntry(parent.itemId, entry)
        }
    }

    override fun isChildDocument(parentDocumentId: String, documentId: String): Boolean = reading {
        val parent = target(parentDocumentId)
        val child = target(documentId)
        if (parent.itemId != child.itemId) return false
        val root = safeRootId()
        var current = child.entry
        // The engine refuses cycles; the bound is so a damaged tree can't hold this thread forever.
        repeat(MAX_DEPTH) {
            if (current == parent.entry) return true
            if (current == root) return false
            current = child.drive.entry(current).parent
        }
        false
    }

    override fun openDocument(documentId: String, mode: String, signal: CancellationSignal?): ParcelFileDescriptor = reading {
        val target = target(documentId)
        val entry = target.drive.entry(target.entry)
        if (entry.folder) throw FileNotFoundException("this is a folder")
        val flags = ParcelFileDescriptor.parseMode(mode)
        val access = flags and ParcelFileDescriptor.MODE_READ_WRITE
        val truncating = access != ParcelFileDescriptor.MODE_READ_ONLY && flags and ParcelFileDescriptor.MODE_TRUNCATE != 0
        val appending = flags and ParcelFileDescriptor.MODE_APPEND != 0
        val file = SafeFile(
            drive = target.drive,
            id = target.entry,
            // A proxy descriptor can't be opened for appending: its position 0 is the end instead.
            start = if (appending && !truncating) entry.size.toLong() else 0L,
            changedAlready = truncating,
            onChanged = { notifyChildren(target.itemId, entry.parent) },
        )
        val descriptor = try {
            appContext.getSystemService(StorageManager::class.java).openProxyFileDescriptor(access, file, files)
        } catch (error: IOException) {
            throw FileNotFoundException(error.toString())
        }
        // Only now: if the descriptor can't be made, the file stays as it was.
        if (truncating) {
            try {
                target.drive.truncate(target.entry, 0uL)
            } catch (error: VaultException) {
                descriptor.close()
                throw error
            }
        }
        descriptor
    }

    override fun createDocument(parentDocumentId: String, mimeType: String, displayName: String): String = reading {
        val parent = target(parentDocumentId)
        val folder = mimeType == Document.MIME_TYPE_DIR
        val wanted = if (folder) displayName else SafeDocuments.withExtension(displayName, MimeTypeMap.getSingleton().getExtensionFromMimeType(mimeType))
        val entry = synchronized(naming) {
            val name = SafeDocuments.uniqueName(wanted, parent.drive.list(parent.entry).map { it.name }.toSet())
            if (folder) parent.drive.createFolder(parent.entry, name) else parent.drive.createFile(parent.entry, name)
        }
        notifyChildren(parent.itemId, parent.entry)
        SafeDocuments.documentId(parent.itemId, entry.id)
    }

    override fun renameDocument(documentId: String, displayName: String): String? = reading {
        val target = target(documentId)
        val entry = target.drive.entry(target.entry)
        synchronized(naming) {
            val siblings = target.drive.list(entry.parent).filter { it.id != entry.id }.map { it.name }.toSet()
            target.drive.rename(entry.id, entry.parent, SafeDocuments.uniqueName(displayName, siblings))
        }
        notifyChildren(target.itemId, entry.parent)
        // The object keeps its id.
        null
    }

    /** Inside one Safe. Between two, the keys differ, so the Files app copies and deletes instead. */
    override fun moveDocument(sourceDocumentId: String, sourceParentDocumentId: String, targetParentDocumentId: String): String = reading {
        val source = target(sourceDocumentId)
        val folder = target(targetParentDocumentId)
        if (source.itemId != folder.itemId) throw UnsupportedOperationException("each Safe has its own keys")
        val entry = source.drive.entry(source.entry)
        synchronized(naming) {
            val name = SafeDocuments.uniqueName(entry.name, source.drive.list(folder.entry).filter { it.id != entry.id }.map { it.name }.toSet())
            source.drive.rename(entry.id, folder.entry, name)
        }
        notifyChildren(source.itemId, entry.parent)
        notifyChildren(source.itemId, folder.entry)
        // Non-null even though the id stays: a null here makes the Files app copy it as well.
        sourceDocumentId
    }

    override fun deleteDocument(documentId: String) = reading {
        val target = target(documentId)
        val entry = target.drive.entry(target.entry)
        target.drive.remove(entry.id)
        notifyChildren(target.itemId, entry.parent)
    }

    private companion object {
        const val MAX_DEPTH = 4096

        val ROOT_COLUMNS = arrayOf(
            Root.COLUMN_ROOT_ID,
            Root.COLUMN_DOCUMENT_ID,
            Root.COLUMN_TITLE,
            Root.COLUMN_SUMMARY,
            Root.COLUMN_FLAGS,
            Root.COLUMN_ICON,
            Root.COLUMN_AVAILABLE_BYTES,
        )
        val DOCUMENT_COLUMNS = arrayOf(
            Document.COLUMN_DOCUMENT_ID,
            Document.COLUMN_DISPLAY_NAME,
            Document.COLUMN_MIME_TYPE,
            Document.COLUMN_SIZE,
            Document.COLUMN_LAST_MODIFIED,
            Document.COLUMN_FLAGS,
        )
    }
}

/**
 * One open file. The other app's reads and writes arrive here and go straight to the engine, which
 * keeps pending writes sealed in its staging file. Once the vault locks, every call fails: the
 * drive has no keys. Plaintext only passes through memory, and these buffers are wiped after use.
 */
private class SafeFile(
    private val drive: SafeDrive,
    private val id: String,
    private val start: Long,
    changedAlready: Boolean,
    private val onChanged: () -> Unit,
) : ProxyFileDescriptorCallback() {
    private var changed = changedAlready

    private inline fun <T> call(name: String, work: () -> T): T = try {
        work()
    } catch (error: VaultException) {
        throw ErrnoException(name, OsConstants.EIO)
    }

    override fun onGetSize(): Long = call("fstat") { drive.entry(id).size.toLong() - start }

    override fun onRead(offset: Long, size: Int, data: ByteArray): Int = call("read") {
        val plain = drive.read(id, (start + offset).toULong(), size.toUInt())
        plain.copyInto(data)
        plain.fill(0)
        plain.size
    }

    override fun onWrite(offset: Long, size: Int, data: ByteArray): Int = call("write") {
        val plain = data.copyOf(size)
        try {
            drive.write(id, (start + offset).toULong(), plain)
        } finally {
            plain.fill(0)
        }
        changed = true
        size
    }

    override fun onFsync() = call("fsync") { drive.flush(id) }

    /** The app closed it, so what it wrote becomes a new revision. */
    override fun onRelease() {
        if (!changed) return
        try {
            drive.flush(id)
        } catch (error: VaultException) {
            // Nobody is left to tell. Locked means locking sealed it; otherwise the engine keeps
            // the staged data for the next flush.
            Log.w("OctaPassSafes", "Sealing a file: $error")
        }
        onChanged()
    }
}
