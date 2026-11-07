package app.octap.android.ui.auth

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.wrapContentWidth
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
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
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import app.octap.android.BuildConfig
import app.octap.android.model.AppModel
import app.octap.android.model.errorMessage
import app.octap.android.model.isCode
import app.octap.android.ui.components.Alert
import app.octap.android.ui.components.AuthLayout
import app.octap.android.ui.components.Field
import app.octap.android.ui.components.LinkButton
import app.octap.android.ui.components.PasswordField
import app.octap.android.ui.components.PrimaryButton
import app.octap.android.ui.local.LocalChoices
import app.octap.resources.R
import app.octap.vault.ErrorCode
import app.octap.vault.PendingTwoStep
import app.octap.vault.SignInResult
import app.octap.vault.TwoStepMethod
import app.octap.vault.normalizeSecretKey
import kotlinx.coroutines.launch

/** What the web vault accepts as an email (`isValidEmail`). */
fun isValidEmail(email: String) = Regex("^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$").matches(email)

fun normalizeEmail(email: String) = email.trim().lowercase()

/** `https`, or `http` to this device for development, as the web vault's sign-in checks it. */
fun isSecureServerUrl(url: String): Boolean {
    val trimmed = url.trim()
    return Regex("^https://.+", RegexOption.IGNORE_CASE).containsMatchIn(trimmed) ||
        Regex("^http://(localhost|127\\.0\\.0\\.1)", RegexOption.IGNORE_CASE).containsMatchIn(trimmed)
}

/** The server choice (`ServerPicker`): Octa Pass, or a self-hosted server's address. */
data class ServerChoice(val self: Boolean, val url: String) {
    val serverUrl: String get() = if (self) url.trim() else BuildConfig.DEFAULT_SERVER_URL

    companion object {
        val HOSTED = ServerChoice(false, BuildConfig.DEFAULT_SERVER_URL)
    }
}

@Composable
fun ServerPicker(value: ServerChoice, onChange: (ServerChoice) -> Unit, error: String?) {
    Column {
        Text(stringResource(R.string.server_legend), style = MaterialTheme.typography.labelLarge)
        SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
            SegmentedButton(
                selected = !value.self,
                onClick = { onChange(ServerChoice.HOSTED) },
                shape = SegmentedButtonDefaults.itemShape(0, 2),
                modifier = Modifier.testTag("server.hosted"),
            ) { Text(stringResource(R.string.server_hosted)) }
            SegmentedButton(
                selected = value.self,
                onClick = { if (!value.self) onChange(ServerChoice(true, "https://")) },
                shape = SegmentedButtonDefaults.itemShape(1, 2),
                modifier = Modifier.testTag("server.self"),
            ) { Text(stringResource(R.string.server_selfHosted)) }
        }
    }
    if (value.self) {
        Field(
            value = value.url,
            onValueChange = { onChange(ServerChoice(true, it)) },
            label = stringResource(R.string.server_urlLabel),
            placeholder = "https://vault.example.com",
            hint = stringResource(R.string.server_urlHint),
            error = error,
            keyboardType = KeyboardType.Uri,
            mono = false,
            modifier = Modifier.testTag("server.url"),
        )
    }
}

private data class SignInErrors(val email: String? = null, val password: String? = null, val secretKey: String? = null, val server: String? = null) {
    val any get() = email != null || password != null || secretKey != null || server != null
}

/** Sign in on this device (`SignIn`), then the second step when the account has two-step sign-in on. */
@Composable
fun SignInScreen(model: AppModel, onCreateAccount: () -> Unit, onForgotPassword: (String) -> Unit, onUseLocal: () -> Unit, onRestore: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val remembered = remember { model.vault.snapshot().rememberedAccounts }
    var email by rememberSaveable { mutableStateOf(remembered.firstOrNull()?.email.orEmpty()) }
    var password by remember { mutableStateOf("") }
    var secretKey by remember { mutableStateOf("") }
    var server by remember {
        val first = remembered.firstOrNull()
        mutableStateOf(if (first != null && first.serverUrl != ServerChoice.HOSTED.url) ServerChoice(true, first.serverUrl) else ServerChoice.HOSTED)
    }
    var showServer by rememberSaveable { mutableStateOf(server.self) }
    var errors by remember { mutableStateOf(SignInErrors()) }
    var formError by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    var twoStep by remember { mutableStateOf<List<TwoStepMethod>?>(null) }

    // A second step left waiting (the app was closed while the user read a code) comes back here.
    LaunchedEffect(Unit) {
        when (val waiting = model.vault.pendingTwoStep()) {
            is PendingTwoStep.Required -> twoStep = waiting.methods
            PendingTwoStep.Expired -> {
                formError = context.getString(R.string.errors_twoStepExpired)
                model.vault.cancelTwoStep()
            }
            null -> Unit
        }
    }

    // The Secret Key lives on each signed-in device. Ask for it only where this account isn't known yet.
    val knownDevice = remembered.any { it.email == normalizeEmail(email) && it.serverUrl == server.serverUrl }
    // Replacing the key on another device leaves this phone remembering the old one.
    var replaceSecretKey by rememberSaveable { mutableStateOf(false) }
    val needsSecretKey = !knownDevice || replaceSecretKey

    fun validate(): SignInErrors = SignInErrors(
        email = if (!isValidEmail(normalizeEmail(email))) context.getString(R.string.validation_email) else null,
        password = if (password.isEmpty()) context.getString(R.string.validation_passwordRequired) else null,
        secretKey = if (needsSecretKey && runCatching { normalizeSecretKey(secretKey) }.isFailure) {
            context.getString(if (secretKey.isNotBlank()) R.string.errors_invalidSecretKey else R.string.validation_secretKeyRequired)
        } else {
            null
        },
        server = if (server.self && !isSecureServerUrl(server.url)) context.getString(R.string.errors_insecureServerUrl) else null,
    )

    fun submit() {
        val found = validate()
        errors = found
        formError = null
        if (found.any || busy) return
        busy = true
        scope.launch {
            try {
                val serverUrl = server.serverUrl
                if (server.self) model.vault.serverInfo(serverUrl)
                val result = model.confirmedUnlock { model.vault.signIn(serverUrl, email, password, if (needsSecretKey) secretKey else null) }
                if (result is SignInResult.TwoStepRequired) {
                    password = ""
                    twoStep = result.methods
                } else if (result is SignInResult.SsoRequired) {
                    // No SSO step in the native apps yet (plan 17): say where it works.
                    formError = context.getString(R.string.sso_notInThisApp, result.orgName)
                }
                // Signed in: the session switches the app to the vault.
            } catch (error: Exception) {
                formError = errorMessage(context, error)
            } finally {
                busy = false
            }
        }
    }

    val methods = twoStep
    if (methods != null) {
        TwoStepScreen(
            model = model,
            methods = methods,
            onStartOver = { error ->
                model.vault.cancelTwoStep()
                twoStep = null
                formError = error
            },
        )
        return
    }

    AuthLayout(
        title = stringResource(R.string.signIn_title),
        subtitle = stringResource(R.string.signIn_subtitle),
        footer = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(stringResource(R.string.signIn_noAccount), color = MaterialTheme.colorScheme.onSurfaceVariant)
                LinkButton(stringResource(R.string.signIn_createAccount), onCreateAccount, Modifier.testTag("signIn.createAccount"))
            }
        },
    ) {
        formError?.let { Alert(it, modifier = Modifier.testTag("signIn.error")) }
        Field(
            value = email,
            onValueChange = { email = it },
            label = stringResource(R.string.fields_email),
            error = errors.email,
            keyboardType = KeyboardType.Email,
            contentType = ContentType.Username,
            modifier = Modifier.testTag("signIn.email"),
        )
        PasswordField(
            value = password,
            onValueChange = { password = it },
            label = stringResource(R.string.fields_masterPassword),
            error = errors.password,
            imeAction = if (needsSecretKey) ImeAction.Next else ImeAction.Done,
            onImeAction = { if (!needsSecretKey) submit() },
            modifier = Modifier.testTag("signIn.password"),
        )
        if (knownDevice && !replaceSecretKey) {
            LinkButton(stringResource(R.string.signIn_newSecretKey), { replaceSecretKey = true }, Modifier.testTag("signIn.newSecretKey"))
        }
        if (needsSecretKey) {
            Field(
                value = secretKey,
                onValueChange = { secretKey = it },
                label = stringResource(R.string.fields_secretKey),
                placeholder = "OP1-XXXXXX-XXXXXX-XXXXX-XXXXX-XXXX",
                hint = stringResource(R.string.signIn_secretKeyHint),
                error = errors.secretKey,
                mono = true,
                capitalization = KeyboardCapitalization.Characters,
                keyboardType = KeyboardType.Ascii,
                imeAction = ImeAction.Done,
                onImeAction = ::submit,
                modifier = Modifier.testTag("signIn.secretKey"),
            )
        }
        if (showServer) {
            ServerPicker(server, { server = it }, errors.server)
        } else {
            Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
                Text(
                    stringResource(R.string.signIn_signingInTo, stringResource(R.string.server_hosted)),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    style = MaterialTheme.typography.bodyMedium,
                )
                LinkButton(stringResource(R.string.signIn_changeServer), { showServer = true }, Modifier.wrapContentWidth().testTag("signIn.changeServer"))
            }
        }
        PrimaryButton(stringResource(R.string.signIn_submit), ::submit, busy = busy, modifier = Modifier.testTag("signIn.submit"))
        LinkButton(stringResource(R.string.signIn_forgotPassword), { onForgotPassword(server.serverUrl) }, Modifier.fillMaxWidth().testTag("signIn.forgotPassword"))
        LocalChoices(model, onUseLocal, onRestore)
    }
}

/**
 * The second step of signing in on a new device (`TwoStepForm`). Security keys need the web
 * vault's relying party, which the phone apps don't have yet, so only codes are offered here.
 */
@Composable
fun TwoStepScreen(model: AppModel, methods: List<TwoStepMethod>, onStartOver: (String?) -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val usable = methods.filter { it != TwoStepMethod.SECURITY_KEY }.ifEmpty { listOf(TwoStepMethod.RECOVERY_CODE) }
    var method by remember { mutableStateOf(if (TwoStepMethod.TOTP in usable) TwoStepMethod.TOTP else usable.first()) }
    var code by remember { mutableStateOf("") }
    var fieldError by remember { mutableStateOf<String?>(null) }
    var formError by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }

    fun submit() {
        if (busy) return
        val typed = if (method == TwoStepMethod.TOTP) code.replace(Regex("\\s"), "") else code.trim()
        if (method == TwoStepMethod.TOTP && !Regex("^\\d{6}$").matches(typed)) {
            fieldError = context.getString(R.string.twoStep_codeRequired)
            return
        }
        if (method == TwoStepMethod.RECOVERY_CODE && typed.isEmpty()) {
            fieldError = context.getString(R.string.twoStep_recoveryRequired)
            return
        }
        busy = true
        fieldError = null
        formError = null
        scope.launch {
            try {
                model.confirmedUnlock {
                    model.vault.finishTwoStep(
                        if (method == TwoStepMethod.TOTP) app.octap.vault.TwoStepProof.Totp(typed) else app.octap.vault.TwoStepProof.RecoveryCode(typed),
                    )
                }
            } catch (error: Exception) {
                when {
                    error.isCode(ErrorCode.TWO_STEP_EXPIRED) -> onStartOver(errorMessage(context, error))
                    error.isCode(ErrorCode.INVALID_TWO_STEP_CODE) -> {
                        fieldError = errorMessage(context, error)
                        code = ""
                    }
                    else -> formError = errorMessage(context, error)
                }
            } finally {
                busy = false
            }
        }
    }

    AuthLayout(
        title = stringResource(R.string.twoStep_title),
        subtitle = stringResource(if (method == TwoStepMethod.TOTP) R.string.twoStep_totpSubtitle else R.string.twoStep_recoverySubtitle),
        footer = { LinkButton(stringResource(R.string.twoStep_startOver), { onStartOver(null) }, enabled = !busy, modifier = Modifier.testTag("twoStep.startOver")) },
    ) {
        formError?.let { Alert(it) }
        if (method == TwoStepMethod.TOTP) {
            Field(
                value = code,
                onValueChange = { code = it.filter { c -> c.isDigit() || c == ' ' }.take(7) },
                label = stringResource(R.string.twoStep_codeLabel),
                error = fieldError,
                mono = true,
                keyboardType = KeyboardType.NumberPassword,
                contentType = ContentType.SmsOtpCode,
                imeAction = ImeAction.Done,
                onImeAction = ::submit,
                modifier = Modifier.testTag("twoStep.code"),
            )
        } else {
            Field(
                value = code,
                onValueChange = { code = it },
                label = stringResource(R.string.twoStep_recoveryLabel),
                placeholder = "XXXXX-XXXXX",
                error = fieldError,
                mono = true,
                capitalization = KeyboardCapitalization.Characters,
                keyboardType = KeyboardType.Ascii,
                imeAction = ImeAction.Done,
                onImeAction = ::submit,
                modifier = Modifier.testTag("twoStep.recovery"),
            )
        }
        PrimaryButton(stringResource(R.string.twoStep_verify), ::submit, busy = busy, modifier = Modifier.testTag("twoStep.verify"))
        Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
            for (other in usable.filter { it != method }) {
                LinkButton(
                    stringResource(if (other == TwoStepMethod.TOTP) R.string.twoStep_useCode else R.string.twoStep_useRecovery),
                    {
                        method = other
                        code = ""
                        fieldError = null
                        formError = null
                    },
                    enabled = !busy,
                    modifier = Modifier.testTag("twoStep.use.${other.name.lowercase()}"),
                )
            }
        }
    }
}
