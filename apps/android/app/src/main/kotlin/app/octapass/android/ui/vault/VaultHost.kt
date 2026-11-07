package app.octap.android.ui.vault

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Folder
import androidx.compose.material.icons.outlined.Inventory2
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material3.DrawerValue
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalDrawerSheet
import androidx.compose.material3.ModalNavigationDrawer
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationRail
import androidx.compose.material3.NavigationRailItem
import androidx.compose.material3.PermanentDrawerSheet
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.VerticalDivider
import androidx.compose.material3.rememberDrawerState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.compositionLocalOf
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.navigation3.runtime.NavEntry
import androidx.navigation3.ui.NavDisplay
import app.octap.android.model.AppModel
import app.octap.android.ui.auth.DeviceUnlockOffer
import app.octap.android.ui.local.AccountOnly
import app.octap.resources.R
import kotlinx.coroutines.launch

/** How wide the window is, in Material's window size classes. */
enum class Width { Compact, Medium, Expanded }

/** What every vault screen needs: the model, the navigator, and whether an item opens beside the list. */
class VaultContext(val model: AppModel, val nav: VaultNavigator, val width: Width, val openDrawer: (() -> Unit)?) {
    val twoPane: Boolean get() = width == Width.Expanded

    fun open(route: Route) = nav.open(route, twoPane)

    fun close() = nav.close(twoPane)
}

val LocalVault = compositionLocalOf<VaultContext> { error("no vault") }

/**
 * The unlocked vault (`VaultLayout`): the bottom bar on phones, a rail on small tablets and the
 * sidebar on large ones, the sidebar as a drawer otherwise, and the screens in a back stack with
 * predictive back.
 */
@Composable
fun VaultHost(model: AppModel, nav: VaultNavigator) {
    BoxWithConstraints(Modifier.fillMaxSize()) {
        val width = when {
            maxWidth >= 840.dp -> Width.Expanded
            maxWidth >= 600.dp -> Width.Medium
            else -> Width.Compact
        }
        // An item open beside the list moves on top of it when the window narrows.
        LaunchedEffect(width) {
            val detail = nav.detail
            if (width != Width.Expanded && detail != null) {
                nav.detail = null
                nav.push(detail)
            }
        }
        val drawer = rememberDrawerState(DrawerValue.Closed)
        val scope = rememberCoroutineScope()
        val context = VaultContext(model, nav, width, if (width == Width.Expanded) null else ({ scope.launch { drawer.open() } }))
        BackHandler(enabled = drawer.isOpen) { scope.launch { drawer.close() } }

        CompositionLocalProvider(LocalVault provides context) {
            WifiSaveOffer()
            OpenedLinksReview(context)
            IdentityGateDialog(model)
            val sidebar = @Composable {
                Sidebar(onNavigate = { scope.launch { drawer.close() } })
            }
            if (width == Width.Expanded) {
                Row(Modifier.fillMaxSize()) {
                    PermanentDrawerSheet(Modifier.width(300.dp), drawerContainerColor = MaterialTheme.colorScheme.surfaceContainer) { sidebar() }
                    VerticalDivider()
                    Box(Modifier.weight(1f).fillMaxHeight()) { Screens(context) }
                }
            } else {
                ModalNavigationDrawer(
                    drawerState = drawer,
                    gesturesEnabled = drawer.isOpen,
                    drawerContent = { ModalDrawerSheet(Modifier.width(320.dp)) { sidebar() } },
                ) {
                    if (width == Width.Medium) {
                        Row(Modifier.fillMaxSize()) {
                            TabRail(nav)
                            Box(Modifier.weight(1f).fillMaxHeight()) { Screens(context) }
                        }
                    } else {
                        Scaffold(bottomBar = { if (nav.stack.size == 1) TabBar(nav) }, contentWindowInsets = WindowInsets(0)) { padding ->
                            Box(Modifier.fillMaxSize().padding(bottom = padding.calculateBottomPadding())) { Screens(context) }
                        }
                    }
                }
            }
        }
    }
    DeviceUnlockOffer(model)
}

@Composable
private fun Screens(context: VaultContext) {
    val nav = context.nav
    NavDisplay(
        backStack = nav.stack,
        onBack = { nav.pop() },
        entryProvider = { route -> NavEntry(route) { Screen(it) } },
    )
}

@Composable
private fun Screen(route: Route) {
    when (route) {
        is Route.Items -> ItemsScreen(route.scope)
        is Route.Item -> ItemScreen(route.id)
        is Route.Edit -> EditorScreen(route)
        Route.Generator -> app.octap.android.ui.tools.GeneratorScreen()
        Route.DeveloperTools -> app.octap.android.ui.tools.DeveloperToolsScreen()
        Route.Health -> app.octap.android.ui.tools.HealthScreen()
        is Route.HealthCheck -> app.octap.android.ui.tools.HealthCheckScreen(route.check)
        Route.RecoveryMap -> app.octap.android.ui.tools.RecoveryMapScreen()
        Route.MaskedEmail -> AccountOnly(R.string.nav_maskedEmail) { app.octap.android.ui.tools.MaskedEmailScreen() }
        Route.Safes -> app.octap.android.ui.tools.SafesScreen()
        Route.Settings -> app.octap.android.ui.settings.SettingsScreen()
        Route.ChangePassword -> app.octap.android.ui.settings.ChangePasswordScreen()
        Route.RotateSecretKey -> app.octap.android.ui.settings.RotateSecretKeyScreen()
        Route.VaultKeys -> app.octap.android.ui.settings.VaultKeysScreen()
        Route.SecurityLog -> app.octap.android.ui.settings.SecurityLogScreen()
        Route.Import -> app.octap.android.ui.settings.ImportScreen()
        Route.Scan -> app.octap.android.ui.tools.ScanScreen()
        is Route.AddCode -> app.octap.android.ui.tools.AddCodeScreen(route.itemId)
        is Route.ScanCodes -> app.octap.android.ui.tools.ScanCodesScreen(route.fromLink)
        Route.Sharing -> AccountOnly(R.string.nav_sharing) { app.octap.android.ui.sharing.SharingScreen() }
        is Route.VaultMembers -> AccountOnly(R.string.nav_sharing) { app.octap.android.ui.sharing.VaultMembersScreen(route.vaultId) }
        Route.Emergency -> AccountOnly(R.string.nav_emergency) { app.octap.android.ui.sharing.EmergencyScreen() }
        is Route.EmergencyVault -> AccountOnly(R.string.nav_emergency) { app.octap.android.ui.sharing.EmergencyVaultScreen(route.contactId) }
        is Route.Takeover -> AccountOnly(R.string.nav_emergency) { app.octap.android.ui.sharing.TakeoverScreen(route.contactId, route.email) }
    }
}

private val tabs = listOf(
    Triple(Tab.Items, Icons.Outlined.Inventory2, R.string.nav_items),
    Triple(Tab.Safes, Icons.Outlined.Folder, R.string.fileTools_safesTitle),
    Triple(Tab.Health, Icons.Outlined.Shield, R.string.nav_health),
    Triple(Tab.Settings, Icons.Outlined.Settings, R.string.nav_settings),
)

@Composable
private fun TabBar(nav: VaultNavigator) {
    NavigationBar {
        for ((tab, icon, label) in tabs) {
            NavigationBarItem(
                selected = nav.tab == tab,
                onClick = { nav.select(tab) },
                icon = { Icon(icon, contentDescription = null) },
                label = { Text(stringResource(label)) },
                modifier = Modifier.testTag("tab.${tab.name.lowercase()}"),
            )
        }
    }
}

@Composable
private fun TabRail(nav: VaultNavigator) {
    NavigationRail {
        for ((tab, icon, label) in tabs) {
            NavigationRailItem(
                selected = nav.tab == tab,
                onClick = { nav.select(tab) },
                icon = { Icon(icon, contentDescription = null) },
                label = { Text(stringResource(label)) },
                modifier = Modifier.testTag("tab.${tab.name.lowercase()}"),
            )
        }
    }
}

/**
 * One-time code links the phone opened Octa Pass with (`OpenedLinks`), once the vault is unlocked:
 * they go through the same review as scanned codes. Links that arrive together are reviewed
 * together, so every part of a Google Authenticator export lands in one review.
 */
@Composable
private fun OpenedLinksReview(context: VaultContext) {
    val links by context.model.openedLinks.collectAsState()
    LaunchedEffect(links) {
        if (links.isEmpty() || context.nav.top is Route.ScanCodes) return@LaunchedEffect
        context.model.openedLinks.value = emptyList()
        context.nav.pendingCodes = links
        context.nav.push(Route.ScanCodes(fromLink = true))
    }
}
