package app.octap.android.ui.local

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.DocumentsContract
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts.CreateDocument
import androidx.activity.result.contract.ActivityResultContracts.OpenDocumentTree
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import app.octap.android.model.AppModel
import app.octap.android.model.Toast
import app.octap.resources.R
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.time.LocalDate
import java.time.ZoneOffset

/** Back up now, and the folder automatic backups go to, through the system's pickers. */
class BackupActions(val busy: Boolean, val save: () -> Unit, val chooseFolder: () -> Unit)

/** What the web vault calls a saved backup (`backupFilename`). */
private fun backupFileName() = "octapass-${LocalDate.now(ZoneOffset.UTC)}.octapass-backup"

/** What the folder is called in the picker, for "Backing up to …". */
private fun folderName(context: Context, tree: Uri): String {
    val document = DocumentsContract.buildDocumentUriUsingTree(tree, DocumentsContract.getTreeDocumentId(tree))
    val column = arrayOf(DocumentsContract.Document.COLUMN_DISPLAY_NAME)
    val name = context.contentResolver.query(document, column, null, null, null)?.use { rows ->
        if (rows.moveToFirst()) rows.getString(0) else null
    }
    return name ?: tree.lastPathSegment.orEmpty()
}

/** Gives up access to a folder the vault no longer backs up to: Android keeps a limited number. */
fun releaseFolder(context: Context, folder: String) {
    val access = Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
    runCatching { context.contentResolver.releasePersistableUriPermission(Uri.parse(folder), access) }
}

/** [onDone] runs after a backup is saved or a folder is on; cancelling a picker does nothing. */
@Composable
fun rememberBackupActions(model: AppModel, onDone: () -> Unit = {}): BackupActions {
    val context = LocalContext.current
    val done by rememberUpdatedState(onDone)
    var busy by remember { mutableStateOf(false) }

    fun working(work: suspend () -> Unit) {
        busy = true
        model.launch {
            try {
                work()
            } finally {
                busy = false
            }
        }
    }

    val saveAs = rememberLauncherForActivityResult(CreateDocument("application/octet-stream")) { uri ->
        model.inSystemUi = false
        if (uri == null) return@rememberLauncherForActivityResult
        working {
            val path = model.vault.exportLocalBackup()
            try {
                withContext(Dispatchers.IO) {
                    val output = context.contentResolver.openOutputStream(uri, "wt") ?: error("the document took no output")
                    output.use { target -> File(path).inputStream().use { it.copyTo(target) } }
                }
                // Only a file that reached the chosen place counts as a backup.
                model.vault.localBackupSaved()
            } finally {
                model.vault.closeAttachment(path)
            }
            model.localChanged()
            model.toast(R.string.localVault_backedUp, Toast.Tone.Success)
            done()
        }
    }

    val pickFolder = rememberLauncherForActivityResult(OpenDocumentTree()) { tree ->
        model.inSystemUi = false
        if (tree == null) return@rememberLauncherForActivityResult
        working {
            val access = Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
            context.contentResolver.takePersistableUriPermission(tree, access)
            val name = withContext(Dispatchers.IO) { folderName(context, tree) }
            val before = model.vault.localVaults().firstOrNull { it.current }?.backupFolder
            try {
                model.vault.setBackupFolder(tree.toString(), name)
            } catch (error: Exception) {
                // The vault stays on the folder it had.
                if (before != tree.toString()) releaseFolder(context, tree.toString())
                throw error
            } finally {
                model.localChanged()
            }
            if (before != null && before != tree.toString()) releaseFolder(context, before)
            model.toast(R.string.localVault_folderChosen, Toast.Tone.Success)
            done()
        }
    }

    fun picking(open: () -> Unit) {
        model.inSystemUi = true
        try {
            open()
        } catch (error: ActivityNotFoundException) {
            model.inSystemUi = false
            model.toast(R.string.errors_noFileViewer, Toast.Tone.Danger)
        }
    }

    return BackupActions(
        busy = busy,
        save = { picking { saveAs.launch(backupFileName()) } },
        chooseFolder = { picking { pickFolder.launch(null) } },
    )
}
