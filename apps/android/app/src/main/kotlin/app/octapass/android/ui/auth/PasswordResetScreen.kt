package app.octap.android.ui.auth

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.selection.toggleable
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.autofill.ContentType
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.unit.dp
import app.octap.android.BuildConfig
import app.octap.android.model.AppModel
import app.octap.android.model.errorMessage
import app.octap.android.model.isCode
import app.octap.android.ui.components.Alert
import app.octap.android.ui.components.AlertTone
import app.octap.android.ui.components.AuthLayout
import app.octap.android.ui.components.Field
import app.octap.android.ui.components.LinkButton
import app.octap.android.ui.components.PasswordField
import app.octap.android.ui.components.PrimaryButton
import app.octap.android.ui.components.StrengthHint
import app.octap.android.ui.theme.monoStyle
import app.octap.resources.R
import app.octap.vault.ErrorCode
import app.octap.vault.RecoveryKit
import app.octap.vault.SignInResult
import kotlinx.coroutines.launch

private enum class ResetStep { Email, Code, Password, Kit }

/**
 * "Forgot your master password?" (`Reset` in the web vault): the emailed code, the recovery code
 * from the Recovery Kit, a new master password, and the new kit. Works signed out and locked.
 */
@Composable
fun PasswordResetScreen(model: AppModel, serverUrl: String?, onClose: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var step by rememberSaveable { mutableStateOf(ResetStep.Email) }
    var email by rememberSaveable { mutableStateOf(model.session.value.email ?: model.session.value.rememberedAccounts.firstOrNull()?.email.orEmpty()) }
    var code by remember { mutableStateOf("") }
    var devCode by remember { mutableStateOf<String?>(null) }
    var recoveryCode by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var confirmPassword by remember { mutableStateOf("") }
    var resetId by rememberSaveable { mutableStateOf<String?>(null) }
    var kit by remember { mutableStateOf<RecoveryKit?>(null) }
    var fieldError by remember { mutableStateOf<String?>(null) }
    var formError by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    val estimate = remember(password) { model.vault.estimateStrength(password) }

    fun startOver(error: String? = null) {
        resetId?.let { model.vault.cancelPasswordReset(it) }
        resetId = null
        code = ""
        devCode = null
        recoveryCode = ""
        password = ""
        confirmPassword = ""
        fieldError = null
        formError = error
        step = ResetStep.Email
    }

    fun close() {
        resetId?.let { model.vault.cancelPasswordReset(it) }
        resetId = null
        onClose()
    }

    fun sendCode() {
        formError = null
        fieldError = null
        val address = email.trim()
        if (!isValidEmail(normalizeEmail(address))) {
            fieldError = context.getString(R.string.validation_email)
            return
        }
        busy = true
        scope.launch {
            try {
                val remembered = model.vault.snapshot()
                val normalized = normalizeEmail(address)
                val server = serverUrl
                    ?: remembered.serverUrl
                    ?: remembered.rememberedAccounts.firstOrNull { normalizeEmail(it.email) == normalized }?.serverUrl
                    ?: BuildConfig.DEFAULT_SERVER_URL
                val started = model.vault.startPasswordReset(server, address)
                resetId = started.resetId
                email = address
                devCode = started.devVerificationCode
                step = ResetStep.Code
            } catch (error: Exception) {
                formError = errorMessage(context, error)
            } finally {
                busy = false
            }
        }
    }

    fun verify() {
        val id = resetId ?: return
        formError = null
        fieldError = null
        val typed = code.filter(Char::isDigit)
        if (typed.length != 6) {
            fieldError = context.getString(R.string.validation_code)
            return
        }
        busy = true
        scope.launch {
            try {
                model.vault.verifyPasswordReset(id, typed)
                step = ResetStep.Password
            } catch (error: Exception) {
                when {
                    error.isCode(ErrorCode.INVALID_VERIFICATION_CODE) -> fieldError = errorMessage(context, error)
                    error.isCode(ErrorCode.RESET_EXPIRED) -> startOver(errorMessage(context, error))
                    else -> formError = errorMessage(context, error)
                }
            } finally {
                busy = false
            }
        }
    }

    fun finish() {
        val id = resetId ?: return
        formError = null
        fieldError = null
        val recovery = recoveryCode.trim()
        val problem = when {
            recovery.isEmpty() -> context.getString(R.string.reset_recoveryCodeRequired)
            password.isEmpty() -> context.getString(R.string.validation_passwordRequired)
            estimate.score.toInt() < MIN_SCORE -> context.getString(R.string.validation_passwordTooWeak)
            password != confirmPassword -> context.getString(R.string.validation_passwordsDontMatch)
            else -> null
        }
        if (problem != null) {
            fieldError = problem
            return
        }
        busy = true
        scope.launch {
            try {
                val result = model.confirmedUnlock { model.vault.finishPasswordReset(id, recovery, password) }
                kit = result.recoveryKit
                // A second step is asked when signing in again, with the new password.
                if (result.signIn is SignInResult.TwoStepRequired) model.vault.cancelTwoStep()
                step = ResetStep.Kit
            } catch (error: Exception) {
                when {
                    error.isCode(ErrorCode.INVALID_RECOVERY_CODE) -> fieldError = errorMessage(context, error)
                    error.isCode(ErrorCode.RESET_EXPIRED) -> startOver(errorMessage(context, error))
                    else -> formError = errorMessage(context, error)
                }
            } finally {
                busy = false
            }
        }
    }

    // Back leaves the reset until the new kit, which must be seen: on it, Back does nothing.
    BackHandler(enabled = true) {
        if (step != ResetStep.Kit && !busy) close()
    }

    when (step) {
        ResetStep.Email -> AuthLayout(
            title = stringResource(R.string.reset_title),
            subtitle = stringResource(R.string.reset_subtitle),
            footer = { LinkButton(stringResource(R.string.reset_remembered), ::close, Modifier.fillMaxWidth().testTag("reset.back")) },
        ) {
            formError?.let { Alert(it, modifier = Modifier.testTag("reset.error")) }
            Text(stringResource(R.string.reset_needs), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Field(
                value = email,
                onValueChange = { email = it },
                label = stringResource(R.string.fields_email),
                error = fieldError,
                keyboardType = KeyboardType.Email,
                contentType = ContentType.Username,
                imeAction = ImeAction.Done,
                onImeAction = ::sendCode,
                modifier = Modifier.testTag("reset.email"),
            )
            PrimaryButton(stringResource(R.string.reset_sendCode), ::sendCode, busy = busy, modifier = Modifier.testTag("reset.sendCode"))
        }

        ResetStep.Code -> AuthLayout(
            title = stringResource(R.string.verify_title),
            subtitle = stringResource(R.string.reset_codeSent, email),
            footer = { LinkButton(stringResource(R.string.verify_changeEmail), { startOver() }, enabled = !busy, modifier = Modifier.fillMaxWidth().testTag("reset.startOver")) },
        ) {
            formError?.let { Alert(it, modifier = Modifier.testTag("reset.error")) }
            devCode?.let { dev ->
                Alert(stringResource(R.string.verify_devCode), AlertTone.Info, Modifier.testTag("reset.devCode")) {
                    Text(dev, style = monoStyle.copy(textDirection = TextDirection.Ltr))
                }
            }
            Field(
                value = code,
                onValueChange = { code = it.filter { c -> c.isDigit() || c == ' ' }.take(7) },
                label = stringResource(R.string.verify_codeLabel),
                error = fieldError,
                mono = true,
                keyboardType = KeyboardType.NumberPassword,
                contentType = ContentType.SmsOtpCode,
                imeAction = ImeAction.Done,
                onImeAction = ::verify,
                modifier = Modifier.testTag("reset.code"),
            )
            PrimaryButton(stringResource(R.string.reset_verify), ::verify, busy = busy, modifier = Modifier.testTag("reset.verify"))
        }

        ResetStep.Password -> AuthLayout(
            title = stringResource(R.string.reset_passwordTitle),
            subtitle = stringResource(R.string.reset_passwordSubtitle),
            footer = { LinkButton(stringResource(R.string.reset_back), { startOver() }, enabled = !busy, modifier = Modifier.fillMaxWidth().testTag("reset.startOver")) },
        ) {
            formError?.let { Alert(it, modifier = Modifier.testTag("reset.error")) }
            Field(
                value = recoveryCode,
                onValueChange = { recoveryCode = it },
                label = stringResource(R.string.twoStep_recoveryLabel),
                placeholder = "XXXXX-XXXXX",
                hint = stringResource(R.string.reset_recoveryCodeHint),
                error = fieldError,
                mono = true,
                capitalization = KeyboardCapitalization.Characters,
                keyboardType = KeyboardType.Ascii,
                modifier = Modifier.testTag("reset.recoveryCode"),
            )
            Column {
                PasswordField(
                    value = password,
                    onValueChange = { password = it },
                    label = stringResource(R.string.reset_newPassword),
                    contentType = ContentType.NewPassword,
                    imeAction = ImeAction.Next,
                    modifier = Modifier.testTag("reset.newPassword"),
                )
                StrengthHint(estimate, empty = password.isEmpty())
            }
            PasswordField(
                value = confirmPassword,
                onValueChange = { confirmPassword = it },
                label = stringResource(R.string.fields_confirmPassword),
                contentType = ContentType.NewPassword,
                onImeAction = ::finish,
                modifier = Modifier.testTag("reset.confirmPassword"),
            )
            Text(stringResource(R.string.reset_signsOut), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            PrimaryButton(stringResource(R.string.reset_submit), ::finish, busy = busy, modifier = Modifier.testTag("reset.submit"))
        }

        ResetStep.Kit -> {
            val newKit = kit ?: return
            var saved by rememberSaveable { mutableStateOf(false) }
            AuthLayout(
                title = stringResource(R.string.reset_kitTitle),
                subtitle = stringResource(R.string.reset_kitSubtitle),
                wide = true,
            ) {
                RecoveryKitSheet(newKit.toNew())
                RecoveryKitActions(model, newKit.toNew(), tagPrefix = "reset.kit")
                Row(
                    Modifier
                        .fillMaxWidth()
                        .toggleable(value = saved, role = Role.Checkbox, onValueChange = { saved = it })
                        .padding(vertical = 4.dp)
                        .testTag("reset.kit.confirm"),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Checkbox(checked = saved, onCheckedChange = null)
                    Spacer(Modifier.width(12.dp))
                    Text(stringResource(R.string.reset_kitConfirm), style = MaterialTheme.typography.bodyLarge)
                }
                PrimaryButton(stringResource(R.string.kit_continue), ::close, enabled = saved, modifier = Modifier.testTag("reset.kit.continue"))
            }
        }
    }
}
