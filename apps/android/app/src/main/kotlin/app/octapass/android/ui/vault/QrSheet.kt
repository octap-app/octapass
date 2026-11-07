package app.octap.android.ui.vault

import android.view.WindowManager
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material.icons.outlined.Fingerprint
import androidx.compose.material.icons.outlined.Link
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import app.octap.android.model.errorMessage
import app.octap.android.ui.auth.deviceMethodName
import app.octap.android.ui.components.Alert
import app.octap.android.ui.components.AlertTone
import app.octap.android.ui.components.PasswordField
import app.octap.android.ui.components.PrimaryButton
import app.octap.android.ui.components.QrImage
import app.octap.android.ui.components.SecondaryButton
import app.octap.android.ui.util.findActivity
import app.octap.resources.R
import app.octap.vault.Item
import app.octap.android.ui.components.Field as InputField
import androidx.compose.ui.text.input.KeyboardType
import app.octap.vault.ItemDetails
import app.octap.vault.QrChoice
import app.octap.vault.ShareLinkOptions
import app.octap.vault.bankQrText
import app.octap.vault.UnlockMethods
import app.octap.vault.qrChoices
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/** How long a code shows (plan 01). */
const val QR_SECONDS = 60

private const val GUEST_LINK_HOURS = 24u

@Composable
fun qrChoiceLabel(choice: QrChoice): String = choice.label ?: stringResource(
    when (choice.kind) {
        "contact" -> R.string.phone_choices_contact
        "note" -> R.string.phone_choices_note
        "wifi" -> R.string.phone_choices_wifi
        "password" -> R.string.phone_choices_password
        "both" -> R.string.phone_choices_both
        "totp" -> R.string.phone_choices_totp
        "website" -> R.string.phone_choices_website
        "payment" -> R.string.phone_choices_payment
        "iban" -> R.string.phone_choices_iban
        "address" -> R.string.typedItems_address
        else -> R.string.phone_choices_field
    },
)

/**
 * Show as QR code (`QrSheet`, plan 01): made on the phone, full screen at full brightness, gone
 * after a minute or when the vault locks. Secrets ask for the device lock or the master password
 * first, unless the user answered this unlock ([AppModel.unlockCoversReveal]), and say that
 * cameras can see the screen.
 */
@Composable
fun QrSheet(item: Item, onClose: () -> Unit) {
    val choices = remember(item) { qrChoices(item) }
    if (choices.isEmpty()) return onClose()
    var choiceId by remember { mutableStateOf(choices.first().id) }
    var confirmed by remember { mutableStateOf(false) }
    val model = LocalVault.current.model
    // The unlock covers secrets ([AppModel.unlockCoversReveal]); null while it's being asked.
    var unlockCovers by remember { mutableStateOf<Boolean?>(null) }
    LaunchedEffect(Unit) { unlockCovers = model.unlockCoversReveal() }
    val choice = choices.firstOrNull { it.id == choiceId } ?: choices.first()
    FullBrightness()
    Dialog(onDismissRequest = onClose, properties = DialogProperties(usePlatformDefaultWidth = false)) {
        Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
            Column(
                Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp).testTag("qr.sheet"),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                androidx.compose.foundation.layout.Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Text(stringResource(R.string.phone_qrTitle), style = MaterialTheme.typography.titleLarge, modifier = Modifier.weight(1f).semantics { heading() })
                    TextButton(onClick = onClose, modifier = Modifier.testTag("qr.close")) { Text(stringResource(R.string.phone_close)) }
                }
                if (choices.size > 1) {
                    Text(stringResource(R.string.phone_qrChoice), style = MaterialTheme.typography.labelLarge, modifier = Modifier.fillMaxWidth())
                    SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                        choices.forEachIndexed { i, c ->
                            SegmentedButton(selected = c.id == choice.id, onClick = { choiceId = c.id }, shape = SegmentedButtonDefaults.itemShape(i, choices.size)) { Text(qrChoiceLabel(c), maxLines = 1) }
                        }
                    }
                }
                if (!choice.confirm || confirmed || unlockCovers == true) {
                    androidx.compose.runtime.key(choice.id) {
                        if (choice.kind == "payment") PaymentCode(item, choice, onClose) else Code(item.title, choice, onClose)
                    }
                } else if (unlockCovers == null) {
                    androidx.compose.material3.CircularProgressIndicator()
                } else {
                    Confirm {
                        model.revealAnswered()
                        confirmed = true
                    }
                }
            }
        }
    }
}

/** Full brightness while a code is up, so another phone's camera reads it. */
@Composable
private fun FullBrightness() {
    val context = LocalContext.current
    DisposableEffect(Unit) {
        val window = context.findActivity()?.window
        val saved = window?.attributes?.screenBrightness
        window?.attributes = window?.attributes?.apply { screenBrightness = WindowManager.LayoutParams.BRIGHTNESS_OVERRIDE_FULL }
        onDispose { window?.attributes = window?.attributes?.apply { screenBrightness = saved ?: WindowManager.LayoutParams.BRIGHTNESS_OVERRIDE_NONE } }
    }
}

/**
 * A one-time link for one guest for a day (`GuestLink`): the QR holds the link, not the network,
 * and the item stays yours. It's made the same way as Item → Share a copy, and shows as a link
 * under Sharing, where it can be cancelled.
 */
@Composable
fun WifiGuestLink(item: Item) {
    val model = LocalVault.current.model
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var url by remember(item.id) { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val linkWhat = stringResource(R.string.shareLink_linkWhat)

    SecondaryButton(
        stringResource(R.string.wifi_guestAction),
        {
            busy = true
            error = null
            scope.launch {
                try {
                    url = model.vault.createShareLink(item.id, ShareLinkOptions(GUEST_LINK_HOURS, 1u, null)).url
                } catch (e: Exception) {
                    error = errorMessage(context, e)
                } finally {
                    busy = false
                }
            }
        },
        enabled = !busy,
        icon = Icons.Outlined.Link,
        modifier = Modifier.testTag("wifi.guest"),
    )
    error?.let { Alert(it) }
    url?.let { link ->
        FullBrightness()
        AlertDialog(
            onDismissRequest = { url = null },
            title = { Text(stringResource(R.string.wifi_guestAction)) },
            text = {
                Column(Modifier.fillMaxWidth().verticalScroll(rememberScrollState()), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    QrImage(link, 200.dp, stringResource(R.string.wifi_guestQrLabel), Modifier.testTag("wifi.guestQr"))
                    Text(stringResource(R.string.wifi_guestHelp), style = MaterialTheme.typography.bodyMedium)
                    TextButton(onClick = { copy(model, link, linkWhat, secret = true) }, modifier = Modifier.testTag("wifi.guestCopy")) {
                        Icon(Icons.Outlined.ContentCopy, null, Modifier.size(18.dp))
                        Text(stringResource(R.string.shareLink_copyLink), Modifier.padding(start = 6.dp))
                    }
                }
            },
            confirmButton = { TextButton(onClick = { url = null }, modifier = Modifier.testTag("wifi.guestDone")) { Text(stringResource(R.string.common_done)) } },
        )
    }
}

@Composable
private fun Code(title: String, choice: QrChoice, onExpire: () -> Unit) {
    var left by remember { mutableIntStateOf(QR_SECONDS) }
    LaunchedEffect(Unit) {
        while (left > 0) {
            delay(1000)
            left--
        }
        onExpire()
    }
    QrImage(choice.text, 280.dp, stringResource(R.string.phone_qrLabel, title), Modifier.testTag("qr.code"))
    Text(title, style = MaterialTheme.typography.titleMedium, textAlign = TextAlign.Center)
    if (choice.warn) Alert(stringResource(R.string.phone_qrWarning), AlertTone.Warn)
    Text(pluralStringResource(R.plurals.phone_qrHidesIn, left, left), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
}

/** A payment code takes an optional amount and reference; a value that doesn't fit shows no code. */
@Composable
private fun PaymentCode(item: Item, choice: QrChoice, onExpire: () -> Unit) {
    var amount by remember { mutableStateOf("") }
    var reference by remember { mutableStateOf("") }
    val bank = (item.details as? ItemDetails.Structured)?.structured
    val text = bank?.let { bankQrText(it, amount, reference) }
    InputField(amount, { amount = it }, stringResource(R.string.typedItems_bankAmount), keyboardType = KeyboardType.Decimal, modifier = Modifier.testTag("qr.amount"))
    InputField(reference, { reference = it }, stringResource(R.string.typedItems_bankReference), modifier = Modifier.testTag("qr.reference"))
    if (text != null) Code(item.title, choice.copy(text = text), onExpire) else Alert(stringResource(R.string.typedItems_bankQrInvalid))
}

/** Confirm it's you: the device lock when device unlock is on, or the master password (`Confirm`). */
@Composable
fun Confirm(message: String = stringResource(R.string.phone_confirmBody), onConfirmed: () -> Unit) {
    val model = LocalVault.current.model
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var methods by remember { mutableStateOf<UnlockMethods?>(null) }
    var password by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(Unit) { methods = runCatching { model.vault.unlockMethods() }.getOrNull() }

    fun confirm(withPassword: String?) {
        busy = true
        error = null
        scope.launch {
            try {
                model.vault.confirmUser(withPassword)
                onConfirmed()
            } catch (e: Exception) {
                error = errorMessage(context, e)
            } finally {
                busy = false
            }
        }
    }

    val device = methods?.let { it.deviceUnlockEnabled && !it.passwordRequired } == true
    Text(stringResource(R.string.phone_confirmTitle), style = MaterialTheme.typography.titleMedium)
    Text(message, style = MaterialTheme.typography.bodyMedium, textAlign = TextAlign.Center)
    error?.let { Alert(it) }
    if (device) PrimaryButton(stringResource(R.string.phone_confirmDevice, deviceMethodName()), { confirm(null) }, busy = busy && password.isEmpty(), icon = Icons.Outlined.Fingerprint, modifier = Modifier.testTag("qr.confirmDevice"))
    PasswordField(password, { password = it }, stringResource(R.string.phone_confirmPassword), onImeAction = { if (password.isNotEmpty()) confirm(password) }, modifier = Modifier.testTag("qr.password"))
    if (device) SecondaryButton(stringResource(R.string.phone_confirm), { confirm(password) }, enabled = password.isNotEmpty() && !busy, modifier = Modifier.testTag("qr.confirm"))
    else PrimaryButton(stringResource(R.string.phone_confirm), { confirm(password) }, enabled = password.isNotEmpty(), busy = busy, modifier = Modifier.testTag("qr.confirm"))
}
