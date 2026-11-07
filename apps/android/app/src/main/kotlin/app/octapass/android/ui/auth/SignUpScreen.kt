package app.octap.android.ui.auth

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material3.Checkbox
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.unit.dp
import app.octap.android.model.AppModel
import app.octap.android.model.errorMessage
import app.octap.android.model.isCode
import app.octap.android.platform.RecoveryKitPdf
import app.octap.android.ui.components.Alert
import app.octap.android.ui.components.AlertTone
import app.octap.android.ui.components.AuthLayout
import app.octap.android.ui.components.Field
import app.octap.android.ui.components.LinkButton
import app.octap.android.ui.components.Logo
import app.octap.android.ui.components.PasswordField
import app.octap.android.ui.components.PrimaryButton
import app.octap.android.ui.components.QrImage
import app.octap.android.ui.components.StrengthHint
import app.octap.android.ui.theme.Brand
import app.octap.android.ui.theme.monoStyle
import app.octap.android.ui.util.formatDate
import app.octap.resources.R
import app.octap.vault.ErrorCode
import app.octap.vault.NewRecoveryKit
import app.octap.vault.RecoveryKit
import app.octap.vault.SignupMode
import kotlinx.coroutines.launch

private enum class Step { Account, Verify, Kit, Done }

/** A master password must reach "strong" (score 3), as on the web. */
internal const val MIN_SCORE = 3

/** Create an account (`SignUp`): account, email code, Recovery Kit, done. */
@Composable
fun SignUpScreen(model: AppModel, onSignIn: () -> Unit, onFinished: () -> Unit) {
    var step by rememberSaveable { mutableStateOf(Step.Account) }
    var signupId by remember { mutableStateOf("") }
    var signupEmail by remember { mutableStateOf("") }
    var devCode by remember { mutableStateOf<String?>(null) }
    var kit by remember { mutableStateOf<RecoveryKit?>(null) }

    when (step) {
        Step.Account -> AccountStep(model, onSignIn) { id, email, code ->
            signupId = id
            signupEmail = email
            devCode = code
            step = Step.Verify
        }
        Step.Verify -> VerifyStep(model, signupId, signupEmail, devCode, onBack = { step = Step.Account }) {
            kit = it
            step = Step.Kit
        }
        Step.Kit -> kit?.let { KitStep(model, it) { step = Step.Done } }
        Step.Done -> DoneStep(onFinished)
    }
}

@Composable
private fun Progress(step: Step) {
    val index = step.ordinal
    val label = stringResource(R.string.signUp_stepOf, index + 1, Step.entries.size)
    Row(
        Modifier.fillMaxWidth().padding(bottom = 20.dp).semantics(mergeDescendants = true) { contentDescription = label },
        horizontalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        for (i in Step.entries.indices) {
            val color = when {
                i < index -> Brand.colors.free
                i == index -> Brand.colors.trust
                else -> MaterialTheme.colorScheme.outlineVariant
            }
            Spacer(Modifier.weight(1f).height(4.dp).clip(CircleShape).background(color))
        }
    }
}

@Composable
private fun AccountStep(model: AppModel, onSignIn: () -> Unit, onDone: (String, String, String?) -> Unit) {
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
                // Invite-only servers answer `signupsClosed` here for an address that wasn't invited.
                val started = model.vault.startSignup(serverUrl, email, password)
                onDone(started.signupId, normalizeEmail(email), started.devVerificationCode)
            } catch (error: Exception) {
                val serverProblem = error.isCode(ErrorCode.INSECURE_SERVER_URL) || error.isCode(ErrorCode.SERVER_UNREACHABLE)
                if (server.self && serverProblem) serverError = errorMessage(context, error) else formError = errorMessage(context, error)
            } finally {
                busy = false
            }
        }
    }

    AuthLayout(
        title = stringResource(R.string.signUp_title),
        subtitle = stringResource(R.string.signUp_subtitle),
        top = { Progress(Step.Account) },
        footer = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(stringResource(R.string.signUp_haveAccount), color = MaterialTheme.colorScheme.onSurfaceVariant)
                LinkButton(stringResource(R.string.signUp_signIn), onSignIn, Modifier.testTag("signUp.signIn"))
            }
        },
    ) {
        formError?.let { Alert(it, modifier = Modifier.testTag("signUp.error")) }
        Field(
            value = email,
            onValueChange = { email = it },
            label = stringResource(R.string.fields_email),
            error = emailError,
            keyboardType = KeyboardType.Email,
            contentType = ContentType.EmailAddress,
            modifier = Modifier.testTag("signUp.email"),
        )
        Column {
            PasswordField(
                value = password,
                onValueChange = { password = it },
                label = stringResource(R.string.fields_masterPassword),
                error = passwordError,
                imeAction = ImeAction.Next,
                contentType = ContentType.NewPassword,
                modifier = Modifier.testTag("signUp.password"),
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
            modifier = Modifier.testTag("signUp.confirm"),
        )
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            Icon(Icons.Outlined.Info, contentDescription = null, tint = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.size(18.dp))
            Text(stringResource(R.string.signUp_guidance), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        ServerPicker(server, { server = it }, serverError)
        PrimaryButton(stringResource(R.string.signUp_continue), ::submit, busy = busy, modifier = Modifier.testTag("signUp.continue"))
    }
}

@Composable
private fun VerifyStep(model: AppModel, signupId: String, email: String, devCode: String?, onBack: () -> Unit, onDone: (RecoveryKit) -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var code by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }

    fun submit() {
        if (busy) return
        if (!Regex("^\\d{6}$").matches(code.replace(" ", ""))) {
            error = context.getString(R.string.validation_code)
            return
        }
        busy = true
        error = null
        scope.launch {
            try {
                onDone(model.confirmedUnlock { model.vault.finishSignup(signupId, code.replace(" ", "")) })
            } catch (e: Exception) {
                error = errorMessage(context, e)
            } finally {
                busy = false
            }
        }
    }

    AuthLayout(
        title = stringResource(R.string.verify_title),
        subtitle = stringResource(R.string.verify_subtitle, email),
        top = { Progress(Step.Verify) },
    ) {
        if (devCode != null) {
            Alert(stringResource(R.string.verify_devCode), AlertTone.Info, Modifier.testTag("verify.devCode")) {
                Text(devCode, style = monoStyle.copy(textDirection = TextDirection.Ltr), color = Brand.colors.trustText)
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
            modifier = Modifier.testTag("verify.code"),
        )
        PrimaryButton(stringResource(R.string.verify_submit), ::submit, busy = busy, modifier = Modifier.testTag("verify.submit"))
        LinkButton(stringResource(R.string.verify_changeEmail), onBack, Modifier.fillMaxWidth())
    }
}

@Composable
private fun KitStep(model: AppModel, kit: RecoveryKit, onDone: () -> Unit) {
    var saved by rememberSaveable { mutableStateOf(false) }

    AuthLayout(
        title = stringResource(R.string.kit_title),
        subtitle = stringResource(R.string.kit_subtitle),
        top = { Progress(Step.Kit) },
        wide = true,
    ) {
        RecoveryKitSheet(kit.toNew())
        RecoveryKitActions(model, kit.toNew())
        Row(
            Modifier
                .fillMaxWidth()
                .toggleable(value = saved, role = Role.Checkbox, onValueChange = { saved = it })
                .padding(vertical = 4.dp)
                .testTag("kit.confirm"),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Checkbox(checked = saved, onCheckedChange = null)
            Spacer(Modifier.width(12.dp))
            Text(stringResource(R.string.kit_confirm), style = MaterialTheme.typography.bodyLarge)
        }
        PrimaryButton(stringResource(R.string.kit_continue), onDone, enabled = saved, modifier = Modifier.testTag("kit.continue"))
    }
}

/** The kit as the screen shows it (`RecoveryKitSheet`). */
@Composable
fun RecoveryKitSheet(kit: NewRecoveryKit) {
    val shape = MaterialTheme.shapes.large
    Column(
        Modifier
            .fillMaxWidth()
            .clip(shape)
            .border(1.dp, MaterialTheme.colorScheme.outlineVariant, shape)
            .background(MaterialTheme.colorScheme.surfaceContainerLow)
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Logo(36.dp)
            Column {
                Text(stringResource(R.string.kit_sheetTitle), style = MaterialTheme.typography.titleMedium)
                Text(stringResource(R.string.kit_createdOn, formatDate(kit.createdAt)), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        KitField(stringResource(R.string.fields_email), kit.email)
        KitField(stringResource(R.string.kit_server), kit.serverUrl)
        KitField(stringResource(R.string.fields_secretKey), kit.secretKey, mono = true, tag = "kit.secretKey")
        Row(horizontalArrangement = Arrangement.spacedBy(16.dp), verticalAlignment = Alignment.CenterVertically) {
            QrImage(RecoveryKitPdf.setupUri(kit), 112.dp, stringResource(R.string.kit_qrLabel))
            Text(stringResource(R.string.kit_qrHelp), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(stringResource(R.string.kit_recoveryCode), style = MaterialTheme.typography.titleSmall)
            val code = kit.recoveryCode
            if (code != null) {
                Text(code, style = monoStyle.copy(textDirection = TextDirection.Ltr), modifier = Modifier.testTag("kit.recoveryCode"))
            } else {
                Text(stringResource(R.string.kit_recoveryKept), style = MaterialTheme.typography.bodyMedium, modifier = Modifier.testTag("kit.recoveryKept"))
            }
            Text(stringResource(R.string.kit_recoveryHelp), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Text(stringResource(R.string.kit_keepSafe), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun KitField(label: String, value: String, mono: Boolean = false, tag: String? = null) {
    Column {
        Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(
            value,
            style = if (mono) monoStyle.copy(textDirection = TextDirection.Ltr) else MaterialTheme.typography.bodyLarge.copy(textDirection = TextDirection.Ltr),
            modifier = if (tag != null) Modifier.testTag(tag) else Modifier,
        )
    }
}

@Composable
private fun DoneStep(onFinished: () -> Unit) {
    AuthLayout(
        title = stringResource(R.string.done_title),
        subtitle = stringResource(R.string.done_subtitle),
        top = { Progress(Step.Done) },
    ) {
        for ((icon, text) in listOf(
            Icons.Outlined.Lock to R.string.done_fact1,
            Icons.Outlined.Key to R.string.done_fact2,
            Icons.Outlined.Shield to R.string.done_fact3,
        )) {
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp), verticalAlignment = Alignment.CenterVertically) {
                Icon(icon, contentDescription = null, tint = Brand.colors.free, modifier = Modifier.size(20.dp))
                Text(stringResource(text), style = MaterialTheme.typography.bodyLarge)
            }
        }
        Spacer(Modifier.height(8.dp))
        PrimaryButton(stringResource(R.string.done_open), onFinished, modifier = Modifier.testTag("done.open"))
    }
}
