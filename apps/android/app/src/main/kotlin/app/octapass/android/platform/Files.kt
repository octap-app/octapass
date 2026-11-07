package app.octap.android.platform

import android.content.ContentResolver
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.MediaStore
import android.provider.OpenableColumns
import androidx.core.content.FileProvider
import java.io.File
import java.net.URLConnection
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** A file a picker copied into the app's cache, for the vault to encrypt. */
data class PickedFile(val file: File, val name: String, val type: String)

/** File names and media types (from the Tauri plugin); no Android classes, so the JVM tests cover them. */
object FileNames {
    /** What a picked file is called on disk: no folders, no control characters, never hidden. */
    fun safe(name: String?): String {
        val cleaned = name.orEmpty()
            .map { if (it == '/' || it == '\\' || it.isISOControl()) '_' else it }
            .joinToString("")
            .trim()
            .trimStart('.')
            .take(120)
        return cleaned.ifEmpty { "file" }
    }

    /** [name], or `name 2`, `name 3`… so nothing in [folder] is overwritten. */
    fun unique(folder: File, name: String): File {
        val safe = safe(name)
        val dot = safe.lastIndexOf('.').takeIf { it > 0 }
        val stem = dot?.let { safe.substring(0, it) } ?: safe
        val extension = dot?.let { safe.substring(it) } ?: ""
        var candidate = File(folder, safe)
        var index = 2
        while (candidate.exists()) {
            candidate = File(folder, "$stem $index$extension")
            index++
        }
        return candidate
    }

    /** The type the system reported, or one guessed from the name; empty when neither knows. */
    fun mediaType(name: String, reported: String?): String =
        reported?.takeIf { it.isNotBlank() && it != "application/octet-stream" }
            ?: URLConnection.guessContentTypeFromName(name.lowercase(Locale.ROOT))
            ?: reported.orEmpty()

    /** What a viewer is asked to open: never empty, so any app that takes files can offer itself. */
    fun viewType(name: String, type: String): String = mediaType(name, type).ifEmpty { "application/octet-stream" }

    fun photoName(at: Date): String = "Photo ${SimpleDateFormat("yyyy-MM-dd 'at' HH.mm.ss", Locale.ROOT).format(at)}.jpg"

    /** "PDF", "PNG": the extension, or the media subtype when the name has none (`kindOf`). */
    fun kind(name: String, type: String): String? {
        val extension = Regex("\\.([a-z0-9]{1,8})$", RegexOption.IGNORE_CASE).find(name)?.groupValues?.get(1)
        return (extension ?: type.substringAfter('/', "")).uppercase().ifEmpty { null }
    }
}

/**
 * The system's pickers and viewer (from the Tauri plugin): the document picker, the photo picker,
 * the camera app, and `ACTION_VIEW` (or the share sheet when nothing views the file). Picked and
 * decrypted files live in the app's cache, shared only through the app's `FileProvider`.
 */
class Files(private val context: Context) {
    private val authority = "${context.packageName}.fileprovider"

    /** A new folder in the cache for one pick. */
    fun pickFolder(): File = File(context.cacheDir, "picked-${System.nanoTime()}").apply { mkdirs() }

    /** The camera app writes the photo straight to [file], through a content URI. */
    fun cameraIntent(file: File): Intent =
        Intent(MediaStore.ACTION_IMAGE_CAPTURE)
            .putExtra(MediaStore.EXTRA_OUTPUT, uri(file, file.name))
            .addFlags(Intent.FLAG_GRANT_WRITE_URI_PERMISSION or Intent.FLAG_GRANT_READ_URI_PERMISSION)

    fun photoTarget(): File = FileNames.unique(pickFolder(), FileNames.photoName(Date()))

    /** Copies each picked document or photo into a new folder. Call off the main thread. */
    fun copy(uris: List<Uri>): List<PickedFile> {
        val resolver = context.contentResolver
        val folder = pickFolder()
        return uris.map { uri ->
            val name = FileNames.safe(displayName(resolver, uri))
            val target = FileNames.unique(folder, name)
            val input = resolver.openInputStream(uri) ?: error("couldn't read $name")
            input.use { source -> target.outputStream().use { source.copyTo(it) } }
            PickedFile(target, name, FileNames.mediaType(name, resolver.getType(uri)))
        }
    }

    private fun displayName(resolver: ContentResolver, uri: Uri): String? =
        resolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
            if (cursor.moveToFirst()) cursor.getString(0) else null
        } ?: uri.lastPathSegment

    /** Shows the file in the app the user picks for its type; read-only, for this file only. */
    fun viewIntent(file: File, name: String, type: String): Intent =
        Intent(Intent.ACTION_VIEW)
            .setDataAndType(uri(file, name), FileNames.viewType(name, type))
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)

    /** The share sheet, for a file no app here views, or an export. */
    fun shareIntent(file: File, name: String, type: String): Intent =
        Intent.createChooser(
            Intent(Intent.ACTION_SEND)
                .setType(FileNames.viewType(name, type))
                .putExtra(Intent.EXTRA_STREAM, uri(file, name))
                .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION),
            name,
        )

    /** A content URI that other apps see under the file's own name. */
    private fun uri(file: File, name: String): Uri = FileProvider.getUriForFile(context, authority, file, name)
}
