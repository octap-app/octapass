package app.octap.android.ui.vault

import android.Manifest
import android.content.ActivityNotFoundException
import android.content.pm.PackageManager
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts.OpenMultipleDocuments
import androidx.activity.result.contract.ActivityResultContracts.PickMultipleVisualMedia
import androidx.activity.result.contract.ActivityResultContracts.PickVisualMedia
import androidx.activity.result.contract.ActivityResultContracts.RequestPermission
import androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult
import androidx.activity.result.contract.ActivityResultContracts.TakePicture
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.AttachFile
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material.icons.outlined.Description
import androidx.compose.material.icons.outlined.Image
import androidx.compose.material.icons.outlined.PhotoCamera
import androidx.compose.material.icons.outlined.Restore
import androidx.compose.material.icons.outlined.Visibility
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import app.octap.android.model.AppModel
import app.octap.android.model.Toast
import app.octap.android.model.errorMessage
import app.octap.android.platform.FileNames
import app.octap.android.platform.Files
import app.octap.android.platform.PickedFile
import app.octap.android.ui.theme.Brand
import app.octap.android.ui.util.formatBytes
import app.octap.resources.R
import app.octap.vault.Attachment
import app.octap.vault.Item
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

/** The phone's three ways to pick files: the document picker, the photo picker and the camera. */
class FilePicker(val files: () -> Unit, val photos: () -> Unit, val camera: (() -> Unit)?)

/**
 * The system pickers, copying what the user picks into the app's cache (never shared storage);
 * [onPicked] gets the copies, which the vault encrypts and the caller then deletes.
 */
@Composable
fun rememberFilePicker(model: AppModel, onPicked: (List<PickedFile>) -> Unit): FilePicker {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val files = remember { Files(context) }
    val picked by rememberUpdatedState(onPicked)
    var photo by remember { mutableStateOf<File?>(null) }

    fun copy(uris: List<Uri>) {
        model.inSystemUi = false
        if (uris.isEmpty()) return
        scope.launch {
            try {
                picked(withContext(Dispatchers.IO) { files.copy(uris) })
            } catch (error: Exception) {
                model.toastError(error)
            }
        }
    }

    val documents = rememberLauncherForActivityResult(OpenMultipleDocuments()) { copy(it) }
    val media = rememberLauncherForActivityResult(PickMultipleVisualMedia()) { copy(it) }
    val camera = rememberLauncherForActivityResult(TakePicture()) { taken ->
        model.inSystemUi = false
        val file = photo
        photo = null
        if (taken && file != null && file.isFile && file.length() > 0) picked(listOf(PickedFile(file, file.name, "image/jpeg"))) else file?.delete()
    }

    fun takePhoto() {
        val target = files.photoTarget()
        photo = target
        model.inSystemUi = true
        try {
            camera.launch(androidx.core.content.FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", target))
        } catch (error: ActivityNotFoundException) {
            model.inSystemUi = false
            model.toast(R.string.errors_cameraUnavailable, Toast.Tone.Danger)
        }
    }

    val permission = rememberLauncherForActivityResult(RequestPermission()) { granted ->
        if (granted) takePhoto() else model.toast(R.string.errors_cameraUnavailable, Toast.Tone.Danger)
    }
    val hasCamera = context.packageManager.hasSystemFeature(PackageManager.FEATURE_CAMERA_ANY)
    return FilePicker(
        files = {
            model.inSystemUi = true
            documents.launch(arrayOf("*/*"))
        },
        photos = {
            model.inSystemUi = true
            media.launch(PickVisualMediaRequest(PickVisualMedia.ImageAndVideo))
        },
        // Octa Pass declares the camera (for the QR scanner), so the camera app needs it granted too.
        camera = if (!hasCamera) null else ({
            if (ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) takePhoto()
            else permission.launch(Manifest.permission.CAMERA)
        }),
    )
}

/** Opens an attachment in the app the user picks; the decrypted copy is deleted when they come back. */
@Composable
fun rememberAttachmentOpener(
    model: AppModel,
    decrypt: suspend (Attachment, String) -> String = { attachment, itemId -> model.vault.openAttachment(itemId, attachment.id) },
): (itemId: String, attachment: Attachment) -> Unit {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val files = remember { Files(context) }
    var open by remember { mutableStateOf<String?>(null) }
    val viewer = rememberLauncherForActivityResult(StartActivityForResult()) {
        model.inSystemUi = false
        open?.let { model.vault.closeAttachment(it) }
        open = null
    }
    DisposableEffect(Unit) { onDispose { open?.let { model.vault.closeAttachment(it) } } }
    return { itemId, attachment ->
        scope.launch {
            try {
                val path = decrypt(attachment, itemId)
                open = path
                val file = File(path)
                model.inSystemUi = true
                try {
                    viewer.launch(files.viewIntent(file, attachment.name, attachment.mediaType))
                } catch (error: ActivityNotFoundException) {
                    try {
                        viewer.launch(files.shareIntent(file, attachment.name, attachment.mediaType))
                    } catch (error: ActivityNotFoundException) {
                        model.inSystemUi = false
                        model.vault.closeAttachment(path)
                        open = null
                        model.toast(R.string.errors_noFileViewer, Toast.Tone.Danger)
                    }
                }
            } catch (error: Exception) {
                model.toastError(error)
            }
        }
    }
}

@Composable
private fun describe(name: String, type: String, size: Long): String {
    val kind = FileNames.kind(name, type)
    val bytes = formatBytes(size)
    return if (kind != null) stringResource(R.string.files_sizeAndType, bytes, kind) else bytes
}

@Composable
private fun FileRow(name: String, type: String, size: Long, note: String?, muted: Boolean = false, actions: @Composable () -> Unit) {
    Row(
        Modifier.fillMaxWidth().heightIn(min = 56.dp).padding(start = 16.dp, end = 4.dp, top = 6.dp, bottom = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Icon(Icons.Outlined.Description, contentDescription = null, tint = MaterialTheme.colorScheme.onSurfaceVariant)
        Column(Modifier.weight(1f)) {
            Text(name, style = MaterialTheme.typography.bodyLarge, color = if (muted) MaterialTheme.colorScheme.onSurfaceVariant else MaterialTheme.colorScheme.onSurface)
            val meta = describe(name, type, size)
            Text(if (note != null) "$meta · $note" else meta, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        actions()
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun PickButtons(picker: FilePicker, enabled: Boolean) {
    FlowRow(Modifier.padding(horizontal = 16.dp, vertical = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        OutlinedButton(onClick = picker.files, enabled = enabled, modifier = Modifier.testTag("files.pick")) {
            Icon(Icons.Outlined.AttachFile, null, Modifier.size(18.dp))
            Text(stringResource(R.string.files_fromFiles), Modifier.padding(start = 6.dp))
        }
        OutlinedButton(onClick = picker.photos, enabled = enabled, modifier = Modifier.testTag("files.photos")) {
            Icon(Icons.Outlined.Image, null, Modifier.size(18.dp))
            Text(stringResource(R.string.files_fromPhotos), Modifier.padding(start = 6.dp))
        }
        picker.camera?.let { camera ->
            OutlinedButton(onClick = camera, enabled = enabled, modifier = Modifier.testTag("files.camera")) {
                Icon(Icons.Outlined.PhotoCamera, null, Modifier.size(18.dp))
                Text(stringResource(R.string.files_fromCamera), Modifier.padding(start = 6.dp))
            }
        }
    }
}

/**
 * An item's files in the item view (`ItemFiles`): open in the system viewer, add from files, photos
 * or the camera, remove. Each file is encrypted on the phone; offline ones upload later.
 */
@Composable
fun ItemFiles(item: Item, editable: Boolean) {
    val model = LocalVault.current.model
    // Files need a server: a local vault has none.
    if (model.isLocal) return
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var uploading by remember { mutableStateOf<String?>(null) }
    var opening by remember { mutableStateOf<String?>(null) }
    var removing by remember { mutableStateOf<Attachment?>(null) }
    val open = rememberAttachmentOpener(model)
    val picker = rememberFilePicker(model) { picked ->
        scope.launch {
            for (file in picked) {
                uploading = file.name
                try {
                    model.vault.addAttachment(item.id, file.file.path, file.name, file.type)
                    model.toast(context.getString(R.string.files_attached, file.name), Toast.Tone.Success)
                } catch (error: Exception) {
                    model.toast(context.getString(R.string.files_attachFailed, file.name, errorMessage(context, error)), Toast.Tone.Danger)
                } finally {
                    file.file.delete()
                }
            }
            uploading = null
        }
    }
    if (item.attachments.isEmpty() && !editable) return
    val document = item.details is app.octap.vault.ItemDetails.Document
    FieldList(stringResource(if (document) R.string.files_documentTitle else R.string.files_title), Modifier.testTag("files")) {
        for (file in item.attachments) {
            FileRow(
                file.name,
                file.mediaType,
                file.size.toLong(),
                when {
                    opening == file.id -> stringResource(R.string.files_downloading)
                    file.pending -> stringResource(R.string.files_waiting)
                    else -> null
                },
            ) {
                IconButton(onClick = { open(item.id, file) }, modifier = Modifier.testTag("file.open.${file.name}")) {
                    Icon(Icons.Outlined.Visibility, contentDescription = stringResource(R.string.files_open, file.name))
                }
                if (editable) {
                    IconButton(onClick = { removing = file }, modifier = Modifier.testTag("file.remove.${file.name}")) {
                        Icon(Icons.Outlined.Delete, contentDescription = stringResource(R.string.files_remove, file.name), tint = Brand.colors.dangerText)
                    }
                }
            }
        }
        uploading?.let { name ->
            Row(Modifier.fillMaxWidth().padding(16.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                Column {
                    Text(name, style = MaterialTheme.typography.bodyLarge)
                    Text(stringResource(R.string.files_uploading), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
        if (item.attachments.isEmpty() && uploading == null) {
            Text(stringResource(R.string.files_empty), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(16.dp))
        }
        if (editable) {
            PickButtons(picker, uploading == null)
            Text(stringResource(R.string.files_phoneHint), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(start = 16.dp, end = 16.dp, bottom = 12.dp))
        }
    }
    removing?.let { file ->
        AlertDialog(
            onDismissRequest = { removing = null },
            title = { Text(stringResource(R.string.files_removeTitle, file.name)) },
            text = { Text(stringResource(R.string.files_removeBody)) },
            dismissButton = { TextButton(onClick = { removing = null }) { Text(stringResource(R.string.common_cancel)) } },
            confirmButton = {
                TextButton(
                    onClick = {
                        removing = null
                        model.launch {
                            model.vault.removeAttachment(item.id, file.id)
                            model.toast(context.getString(R.string.files_removed, file.name), Toast.Tone.Success)
                        }
                    },
                    modifier = Modifier.testTag("file.removeConfirm"),
                ) { Text(stringResource(R.string.files_removeConfirm), color = Brand.colors.dangerText) }
            },
        )
    }
}

/** What the editor does with files when it saves (`FileChanges`). */
data class FileChanges(val add: List<PickedFile> = emptyList(), val remove: List<String> = emptyList()) {
    val any get() = add.isNotEmpty() || remove.isNotEmpty()
}

/** The editor's files: the item's own, plus files picked to add or marked to remove on save (`EditorFiles`). */
@Composable
fun EditorFiles(original: Item?, changes: FileChanges, onChange: (FileChanges) -> Unit, document: Boolean, error: String?) {
    val model = LocalVault.current.model
    if (model.isLocal) return
    val current by rememberUpdatedState(changes)
    val picker = rememberFilePicker(model) { picked -> onChange(current.copy(add = current.add + picked)) }
    // Picked files nobody saved are deleted when the editor closes.
    DisposableEffect(Unit) { onDispose { current.add.forEach { it.file.delete() } } }
    val files = original?.attachments.orEmpty()
    FieldList(stringResource(if (document) R.string.files_documentTitle else R.string.files_title), Modifier.testTag("editor.files")) {
        if (document) {
            Text(stringResource(R.string.files_documentHint), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(16.dp))
        }
        for (file in files) {
            val removed = file.id in changes.remove
            FileRow(file.name, file.mediaType, file.size.toLong(), if (removed) stringResource(R.string.files_willRemove) else null, muted = removed) {
                if (removed) {
                    IconButton(onClick = { onChange(changes.copy(remove = changes.remove - file.id)) }) {
                        Icon(Icons.Outlined.Restore, contentDescription = stringResource(R.string.files_keep, file.name))
                    }
                } else {
                    IconButton(onClick = { onChange(changes.copy(remove = changes.remove + file.id)) }) {
                        Icon(Icons.Outlined.Delete, contentDescription = stringResource(R.string.files_remove, file.name), tint = Brand.colors.dangerText)
                    }
                }
            }
        }
        for (file in changes.add) {
            FileRow(file.name, file.type, file.file.length(), stringResource(R.string.files_pending)) {
                IconButton(onClick = {
                    file.file.delete()
                    onChange(changes.copy(add = changes.add - file))
                }) {
                    Icon(Icons.Outlined.Delete, contentDescription = stringResource(R.string.files_remove, file.name), tint = Brand.colors.dangerText)
                }
            }
        }
        if (error != null) Text(error, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp))
        PickButtons(picker, true)
    }
}

/** Adds and removes the editor's files after the item saved; the messages of any that failed. */
suspend fun applyFileChanges(model: AppModel, itemId: String, changes: FileChanges, context: android.content.Context): List<String> {
    val failures = mutableListOf<String>()
    for (id in changes.remove) {
        runCatching { model.vault.removeAttachment(itemId, id) }.onFailure { failures += errorMessage(context, it) }
    }
    for (file in changes.add) {
        try {
            model.vault.addAttachment(itemId, file.file.path, file.name, file.type)
        } catch (error: Exception) {
            failures += context.getString(R.string.files_attachFailed, file.name, errorMessage(context, error))
        } finally {
            file.file.delete()
        }
    }
    return failures
}
