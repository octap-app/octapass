package app.octap.android.ui.auth

import android.content.ActivityNotFoundException
import android.content.Intent
import android.print.PrintAttributes
import android.print.PrintManager
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts.CreateDocument
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.selection.toggleable
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Print
import androidx.compose.material.icons.outlined.SaveAlt
import androidx.compose.material.icons.outlined.Share
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import androidx.core.content.FileProvider
import app.octap.android.model.AppModel
import app.octap.android.model.PendingKit
import app.octap.android.model.Toast
import app.octap.android.platform.RecoveryKitPdf
import app.octap.android.ui.components.AuthLayout
import app.octap.android.ui.components.PrimaryButton
import app.octap.android.ui.components.SecondaryButton
import app.octap.resources.R
import app.octap.vault.NewRecoveryKit
import app.octap.vault.RecoveryKit

/** A kit that always has a recovery code, in the form the kit's views take. */
fun RecoveryKit.toNew() = NewRecoveryKit(email, serverUrl, secretKey, recoveryCode, createdAt)

/**
 * A kit from replacing a Secret Key or taking over an account: the only copy away from this
 * phone, so it covers the app until the user says it's saved. Back does nothing here.
 * [AppRoot][app.octap.android.ui.AppRoot] shows it from [AppModel.newKit].
 */
@Composable
fun NewKitScreen(model: AppModel, pending: PendingKit) {
    // Never keyed on the kit: rememberSaveable's inputs are written to the saved state.
    var saved by rememberSaveable { mutableStateOf(false) }
    BackHandler(enabled = true) {}
    AuthLayout(title = pending.title, subtitle = pending.body, wide = true) {
        RecoveryKitSheet(pending.kit)
        RecoveryKitActions(model, pending.kit, tagPrefix = "newKit")
        Row(
            Modifier
                .fillMaxWidth()
                .toggleable(value = saved, role = Role.Checkbox, onValueChange = { saved = it })
                .padding(vertical = 4.dp)
                .testTag("newKit.saved"),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Checkbox(checked = saved, onCheckedChange = null)
            Spacer(Modifier.width(12.dp))
            Text(stringResource(R.string.reset_kitConfirm), style = MaterialTheme.typography.bodyLarge)
        }
        PrimaryButton(
            stringResource(R.string.kit_continue),
            {
                model.newKit.value = null
                pending.done?.let { model.toast(it, Toast.Tone.Success) }
            },
            enabled = saved,
            modifier = Modifier.testTag("newKit.continue"),
        )
    }
}

/** Save, share and print the Recovery Kit shown above (`RecoveryKitActions`). */
@Composable
fun RecoveryKitActions(model: AppModel, kit: NewRecoveryKit, tagPrefix: String = "kit") {
    val context = LocalContext.current
    val saveAs = rememberLauncherForActivityResult(CreateDocument("application/pdf")) { uri ->
        model.inSystemUi = false
        if (uri == null) return@rememberLauncherForActivityResult
        try {
            RecoveryKitPdf.save(context, kit, uri)
            model.toast(R.string.phone_native_kitSaved, Toast.Tone.Success)
        } catch (error: Exception) {
            model.toastError(error)
        }
    }

    SecondaryButton(stringResource(R.string.phone_native_kitSave), {
        model.inSystemUi = true
        saveAs.launch(RecoveryKitPdf.fileName(context))
    }, icon = Icons.Outlined.SaveAlt, modifier = Modifier.testTag("$tagPrefix.save"))
    SecondaryButton(stringResource(R.string.phone_native_kitShare), {
        try {
            val file = RecoveryKitPdf.file(context, kit)
            val uri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
            val send = Intent(Intent.ACTION_SEND).setType("application/pdf").putExtra(Intent.EXTRA_STREAM, uri).addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            model.inSystemUi = true
            context.startActivity(Intent.createChooser(send, file.name))
        } catch (error: ActivityNotFoundException) {
            model.inSystemUi = false
            model.toastError(error)
        }
    }, icon = Icons.Outlined.Share, modifier = Modifier.testTag("$tagPrefix.share"))
    SecondaryButton(stringResource(R.string.kit_print), {
        val printing = context.getSystemService(PrintManager::class.java)
        model.inSystemUi = true
        printing.print(RecoveryKitPdf.fileName(context), RecoveryKitPdf.printAdapter(context, kit), PrintAttributes.Builder().setMediaSize(PrintAttributes.MediaSize.ISO_A4).build())
    }, icon = Icons.Outlined.Print, modifier = Modifier.testTag("$tagPrefix.print"))
}
