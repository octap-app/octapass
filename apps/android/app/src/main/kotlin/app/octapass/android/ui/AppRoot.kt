package app.octap.android.ui

import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import app.octap.android.ui.components.AuthLayout
import app.octap.android.ui.components.PrimaryButton
import app.octap.resources.R
import android.app.Activity
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Snackbar
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.unit.dp
import androidx.core.view.WindowCompat
import app.octap.android.Locales
import app.octap.android.model.AppModel
import app.octap.android.model.LocalFlow
import app.octap.android.model.isLocal
import app.octap.android.ui.auth.LockScreen
import app.octap.android.ui.auth.NewKitScreen
import app.octap.android.ui.auth.PasswordResetScreen
import app.octap.android.ui.auth.SignInScreen
import app.octap.android.ui.auth.SignUpScreen
import app.octap.android.ui.local.CreateLocalScreen
import app.octap.android.ui.local.RestoreBackupScreen
import app.octap.android.ui.local.TurnOnSyncScreen
import app.octap.android.ui.theme.OctaPassTheme
import app.octap.android.ui.theme.isDark
import app.octap.android.ui.util.haptic
import app.octap.android.ui.vault.VaultHost
import app.octap.vault.SessionStatus

/**
 * The app: signed out shows sign-in (or sign-up, which stays on screen through its Recovery
 * Kit even once the account exists), locked shows the lock screen, unlocked the vault. The
 * vault's place is kept while it's locked, as the web vault comes back to the same page. A local
 * vault's setup stays on screen the way sign-up does ([AppModel.localFlow]).
 */
@OptIn(ExperimentalComposeUiApi::class)
@Composable
fun AppRoot(model: AppModel) {
    val settings by model.settings.collectAsState()
    val dark = isDark(settings.theme)
    LaunchedEffect(settings.language) { Locales.apply(settings.language) }
    OctaPassTheme(dark) {
        SystemBarIcons(dark)
        val session by model.session.collectAsState()
        val newKit by model.newKit.collectAsState()
        var signingUp by rememberSaveable { mutableStateOf(false) }
        var resettingPassword by rememberSaveable { mutableStateOf(false) }
        var resetServerUrl by rememberSaveable { mutableStateOf<String?>(null) }
        val localFlow by model.localFlow.collectAsState()
        // The vault's screens survive locking; another account starts at its list. A local vault
        // can be renamed in Settings, so its name doesn't count.
        val navigator = remember(session.email, session.serverUrl) {
            model.navigator(if (session.isLocal) session.serverUrl.orEmpty() else "${session.email}@${session.serverUrl}")
        }
        val snackbar = remember { SnackbarHostState() }
        val context = LocalContext.current
        LaunchedEffect(model) {
            model.toasts.collect { toast ->
                haptic(context, toast.tone)
                snackbar.currentSnackbarData?.dismiss()
                snackbar.showSnackbar(toast.text, withDismissAction = false)
            }
        }
        // Back from sign-up's first step goes to sign-in.
        BackHandler(enabled = signingUp && session.status == SessionStatus.SIGNED_OUT) { signingUp = false }

        val deleted by model.accountDeleted.collectAsState()
        Box(Modifier.fillMaxSize().semantics { testTagsAsResourceId = true }) {
            when {
                localFlow == LocalFlow.Create -> CreateLocalScreen(model, onClose = { model.localFlow.value = null })
                localFlow == LocalFlow.Restore -> RestoreBackupScreen(model, onClose = { model.localFlow.value = null })
                localFlow == LocalFlow.TurnOnSync -> TurnOnSyncScreen(model, onClose = { model.localFlow.value = null })
                deleted -> AuthLayout(title = stringResource(R.string.deleted_title), subtitle = stringResource(R.string.deleted_subtitle)) {
                    PrimaryButton(stringResource(R.string.deleted_backToStart), { model.accountDeleted.value = false }, Modifier.testTag("deleted.back"))
                }
                signingUp -> SignUpScreen(model, onSignIn = { signingUp = false }, onFinished = { signingUp = false })
                session.status == SessionStatus.SIGNED_OUT -> SignInScreen(
                    model,
                    onCreateAccount = { signingUp = true },
                    onForgotPassword = { resetServerUrl = it; resettingPassword = true },
                    onUseLocal = { model.localFlow.value = LocalFlow.Create },
                    onRestore = { model.localFlow.value = LocalFlow.Restore },
                )
                // Switching between local vaults goes from one lock screen to the next, password field and all.
                session.status == SessionStatus.LOCKED -> key(session.serverUrl) {
                    LockScreen(
                        model,
                        onForgotPassword = { resetServerUrl = session.serverUrl; resettingPassword = true },
                    )
                }
                else -> VaultHost(model, navigator)
            }
            if (resettingPassword) {
                PasswordResetScreen(model, resetServerUrl, onClose = { resettingPassword = false })
            }
            // Over the vault's screens, and held by the model: while the vault is locked it waits
            // behind the lock screen, and unlocking brings it back.
            if (session.status == SessionStatus.UNLOCKED) newKit?.let { NewKitScreen(model, it) }
            SnackbarHost(snackbar, Modifier.align(Alignment.BottomCenter).navigationBarsPadding().imePadding().padding(bottom = 72.dp)) { data ->
                Snackbar(
                    containerColor = MaterialTheme.colorScheme.inverseSurface,
                    contentColor = MaterialTheme.colorScheme.inverseOnSurface,
                    shape = MaterialTheme.shapes.medium,
                ) { Text(data.visuals.message) }
            }
        }
    }
}

/** Dark icons on light screens and light ones on dark, following the app's theme, not only the phone's. */
@Composable
private fun SystemBarIcons(dark: Boolean) {
    val view = LocalView.current
    if (view.isInEditMode) return
    SideEffect {
        val window = (view.context as? Activity)?.window ?: return@SideEffect
        WindowCompat.getInsetsController(window, view).apply {
            isAppearanceLightStatusBars = !dark
            isAppearanceLightNavigationBars = !dark
        }
    }
}
