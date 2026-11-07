package app.octap.android.ui.local

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.autofill.ContentType
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.unit.dp
import app.octap.android.model.AppModel
import app.octap.android.model.errorMessage
import app.octap.android.model.isCode
import app.octap.android.ui.auth.MIN_SCORE
import app.octap.android.ui.auth.RecoveryKitActions
import app.octap.android.ui.auth.toNew
import app.octap.android.ui.auth.RecoveryKitSheet
import app.octap.android.ui.auth.ServerChoice
import app.octap.android.ui.auth.ServerPicker
import app.octap.android.ui.auth.isSecureServerUrl
import app.octap.android.ui.auth.isValidEmail
import app.octap.android.ui.auth.normalizeEmail
import app.octap.android.ui.components.Alert
import app.octap.android.ui.components.AlertTone
import app.octap.android.ui.components.AuthLayout
import app.octap.android.ui.components.Field
import app.octap.android.ui.components.LinkButton
import app.octap.android.ui.components.PasswordField
import app.octap.android.ui.components.PrimaryButton
import app.octap.android.ui.components.StrengthHint
import app.octap.android.ui.theme.Brand
import app.octap.android.ui.theme.monoStyle
import app.octap.resources.R
import app.octap.vault.ErrorCode
import app.octap.vault.RecoveryKit
import app.octap.vault.SessionStatus
import app.octap.vault.SignupMode
import kotlinx.coroutines.launch

private data class Pending(val id: String, val email: String, val devCode: String?)

/**
 * Turn on sync (`TurnOnSync`): the sign-up steps, but the vault keeps its keys and items and moves
 * into the new account. Finishing changes the session, so
 * [AppRoot][app.octap.android.ui.AppRoot] keeps this up through the Recovery Kit until [onClose].
 */
@Composable
fun TurnOnSyncScreen(model: AppModel, onClose: () -> Unit) {
    val session by model.session.collectAsState()
    var pending by remember { mutableStateOf<Pending?>(null) }
    var kit by remember { mutableStateOf<RecoveryKit?>(null) }
    var finishing by remember { mutableStateOf(false) }

    // Locked before the account exists, this can't go on. The kit stays: it won't show again.
    LaunchedEffect(session.status, kit, finishing) {
        if (kit == null && !finishing && session.status != SessionStatus.UNLOCKED) onClose()
    }

    val shown = kit
    val waiting = pending
    when {
        shown != null -> KitStep(model, shown, onClose)
        waiting != null -> VerifyStep(model, waiting, onFinishing = { finishing = it }, onBack = { pending = null }) { kit = it }
        else -> AccountStep(model, onClose) { pending = it }
    }
}

@Composable
private fun AccountStep(model: AppModel, onBack: () -> Unit, onDone: (Pending) -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var email by rememberSaveable { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var server by remember { mutableStateOf(ServerChoice.HOSTED) }
    var emailError by remember { mutableStateOf<String?>(null) }
    var passwordError by remember { mutableStateOf<String?>(null) }
    var confirmError by remember { mutableStateOf<String?>(null) }
    var serverError by remember { mutableStateOf<String?>(null) }
    var formError by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    val estimate = remember(password) { model.vault.estimateStrength(password) }
    BackHandler(enabled = !busy, onBack = onBack)

    fun submit() {
        if (busy) return
        emailError = if (!isValidEmail(normalizeEmail(email))) context.getString(R.string.validation_email) else null
        passwordError = when {
            password.isEmpty() -> context.getString(R.string.validation_passwordRequired)
            estimate.score.toInt() < MIN_SCORE -> context.getString(R.string.validation_passwordTooWeak)
            else -> null
        }
        confirmError = if (confirm != password) context.getString(R.string.validation_passwordsDontMatch) else null
        serverError = if (server.self && !isSecureServerUrl(server.url)) context.getString(R.string.errors_insecureServerUrl) else null
        formError = null
        if (emailError != null || passwordError != null || confirmError != null || serverError != null) return
        busy = true
        scope.launch {
            try {
                val serverUrl = server.serverUrl
                val info = model.vault.serverInfo(serverUrl)
                if (info.signups == SignupMode.CLOSED) {
                    formError = context.getString(R.string.errors_signupsClosed)
                    return@launch
                }
                val started = model.vault.startTurnOnSync(serverUrl, email, password)
                onDone(Pending(started.signupId, normalizeEmail(email), started.devVerificationCode))
            } catch (error: Exception) {
                val serverProblem = error.isCode(ErrorCode.INSECURE_SERVER_URL) || error.isCode(ErrorCode.SERVER_UNREACHABLE)
                if (server.self && serverProblem) serverError = errorMessage(context, error) else formError = errorMessage(context, error)
            } finally {
                busy = false
            }
        }
    }

    AuthLayout(
        title = stringResource(R.string.localVault_syncTitle),
        subtitle = stringResource(R.string.localVault_syncSubtitle),
        footer = { LinkButton(stringResource(R.string.common_back), onBack, enabled = !busy, modifier = Modifier.testTag("sync.back")) },
    ) {
        formError?.let { Alert(it, modifier = Modifier.testTag("sync.error")) }
        Field(
            value = email,
            onValueChange = { email = it },
            label = stringResource(R.string.fields_email),
            error = emailError,
            keyboardType = KeyboardType.Email,
            contentType = ContentType.EmailAddress,
            modifier = Modifier.testTag("sync.email"),
        )
        Column {
            PasswordField(
                value = password,
                onValueChange = { password = it },
                label = stringResource(R.string.fields_masterPassword),
                error = passwordError,
                imeAction = ImeAction.Next,
                contentType = ContentType.NewPassword,
                modifier = Modifier.testTag("sync.password"),
            )
            StrengthHint(estimate, empty = password.isEmpty())
        }
        PasswordField(
            value = confirm,
            onValueChange = { confirm = it },
            label = stringResource(R.string.fields_confirmPassword),
            error = confirmError,
            contentType = ContentType.NewPassword,
            onImeAction = ::submit,
            modifier = Modifier.testTag("sync.confirm"),
        )
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            Icon(Icons.Outlined.Info, contentDescription = null, tint = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.size(18.dp))
            Text(stringResource(R.string.signUp_guidance), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        ServerPicker(server, { server = it }, serverError)
        PrimaryButton(stringResource(R.string.signUp_continue), ::submit, busy = busy, modifier = Modifier.testTag("sync.continue"))
    }
}

@Composable
private fun VerifyStep(model: AppModel, pending: Pending, onFinishing: (Boolean) -> Unit, onBack: () -> Unit, onDone: (RecoveryKit) -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var code by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    BackHandler(enabled = !busy, onBack = onBack)

    fun submit() {
        if (busy) return
        val typed = code.replace(" ", "")
        if (!Regex("^\\d{6}$").matches(typed)) {
            error = context.getString(R.string.validation_code)
            return
        }
        busy = true
        error = null
        onFinishing(true)
        scope.launch {
            try {
                onDone(model.confirmedUnlock { model.vault.finishTurnOnSync(pending.id, typed) })
            } catch (e: Exception) {
                error = errorMessage(context, e)
            } finally {
                busy = false
                onFinishing(false)
            }
        }
    }

    AuthLayout(
        title = stringResource(R.string.verify_title),
        subtitle = stringResource(R.string.verify_subtitle, pending.email),
    ) {
        if (pending.devCode != null) {
            Alert(stringResource(R.string.verify_devCode), AlertTone.Info, Modifier.testTag("sync.devCode")) {
                Text(pending.devCode, style = monoStyle.copy(textDirection = TextDirection.Ltr), color = Brand.colors.trustText)
            }
        }
        Field(
            value = code,
            onValueChange = { code = it.filter { c -> c.isDigit() || c == ' ' }.take(7) },
            label = stringResource(R.string.verify_codeLabel),
            error = error,
            mono = true,
            keyboardType = KeyboardType.NumberPassword,
            contentType = ContentType.SmsOtpCode,
            imeAction = ImeAction.Done,
            onImeAction = ::submit,
            modifier = Modifier.testTag("sync.code"),
        )
        PrimaryButton(stringResource(R.string.verify_submit), ::submit, busy = busy, modifier = Modifier.testTag("sync.verify"))
        LinkButton(stringResource(R.string.verify_changeEmail), onBack, Modifier.fillMaxWidth(), enabled = !busy)
    }
}

@Composable
private fun KitStep(model: AppModel, kit: RecoveryKit, onDone: () -> Unit) {
    var saved by rememberSaveable { mutableStateOf(false) }
    // Only Continue leaves: the kit can't be shown again.
    BackHandler {}

    AuthLayout(
        title = stringResource(R.string.localVault_syncDoneTitle),
        subtitle = "${stringResource(R.string.localVault_syncDoneSubtitle)} ${stringResource(R.string.kit_subtitle)}",
        wide = true,
    ) {
        RecoveryKitSheet(kit.toNew())
        RecoveryKitActions(model, kit.toNew())
        ConfirmRow(stringResource(R.string.kit_confirm), saved, { saved = it }, Modifier.testTag("kit.confirm"))
        PrimaryButton(stringResource(R.string.kit_continue), onDone, enabled = saved, modifier = Modifier.testTag("kit.continue"))
    }
}
