package app.octap.android.ui.tools

import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.KeyboardArrowRight
import androidx.compose.material.icons.outlined.CalendarMonth
import androidx.compose.material.icons.outlined.Check
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material.icons.outlined.CreditCard
import androidx.compose.material.icons.outlined.ErrorOutline
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material.icons.outlined.LockOpen
import androidx.compose.material.icons.outlined.Mail
import androidx.compose.material.icons.outlined.Phone
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material.icons.outlined.Schedule
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material.icons.outlined.VisibilityOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import app.octap.android.model.errorMessage
import app.octap.android.ui.components.Alert
import app.octap.android.ui.components.AlertTone
import app.octap.android.ui.components.Avatar
import app.octap.android.ui.components.Page
import app.octap.android.ui.components.strengthLabelRes
import app.octap.android.ui.theme.Brand
import app.octap.android.ui.util.formatDate
import app.octap.android.ui.util.rememberLive
import app.octap.android.ui.vault.Empty
import app.octap.android.ui.vault.GeneratorSheet
import app.octap.android.ui.vault.LocalVault
import app.octap.android.ui.vault.Route
import app.octap.android.ui.vault.healthTone
import app.octap.android.ui.vault.providerName
import app.octap.resources.R
import app.octap.vault.EmailBreachCheck
import app.octap.vault.EmailBreachFinding
import app.octap.vault.HealthEntry
import app.octap.vault.HealthReport
import app.octap.vault.RecoveryContact
import app.octap.vault.RecoveryKind
import kotlinx.coroutines.launch

/** A top-level page shows the menu on phones; a deeper one, Back. */
@Composable
fun VaultPage(title: String, subtitle: String? = null, tag: String? = null, actions: @Composable () -> Unit = {}, content: @Composable ColumnScope.() -> Unit) {
    val vault = LocalVault.current
    val deep = vault.nav.stack.size > 1
    Page(
        title = title,
        subtitle = subtitle,
        onBack = if (deep) ({ vault.nav.pop() }) else null,
        onMenu = if (!deep) vault.openDrawer else null,
        actions = actions,
        tag = tag,
        content = content,
    )
}

/** The generator page (`GeneratorPage`). */
@Composable
fun GeneratorScreen() {
    val model = LocalVault.current.model
    VaultPage(stringResource(R.string.generator_title), stringResource(R.string.generator_subtitle), tag = "generator.title") {
        GeneratorPanel(model)
        Text(stringResource(R.string.generator_localNote), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        AliasMakerSection()
    }
}

private fun verdict(score: Int) = when {
    score >= 90 -> R.string.health_verdict_great
    score >= 70 -> R.string.health_verdict_good
    score >= 50 -> R.string.health_verdict_fair
    else -> R.string.health_verdict_poor
}

/**
 * One of Health's checks, with its page (`HealthCheckPage`). The first five always have a tile on
 * Health; the rest get one when they find something. [Dismissed] isn't a tile: Health links to it
 * below them.
 */
enum class HealthCheck(val label: Int, val help: Int, val icon: ImageVector, val always: Boolean = false) {
    Weak(R.string.health_weak, R.string.health_weakHelp, Icons.Outlined.ErrorOutline, always = true),
    Reused(R.string.health_reused, R.string.health_reusedHelp, Icons.Outlined.ContentCopy, always = true),
    Breached(R.string.health_breached, R.string.health_breachedHelp, Icons.Outlined.Shield, always = true),
    TwoStep(R.string.health_missing2fa, R.string.health_missing2faHelp, Icons.Outlined.Schedule, always = true),
    RecoveryEmails(R.string.health_recoveryNo2fa, R.string.health_recoveryNo2faHelp, Icons.Outlined.Mail, always = true),
    RecoveryBreached(R.string.health_recoveryBreached, R.string.health_recoveryBreachedHelp, Icons.Outlined.ErrorOutline),
    Insecure(R.string.health_insecureUrls, R.string.health_insecureUrlsHelp, Icons.Outlined.LockOpen),
    Old(R.string.health_old, R.string.health_oldHelp, Icons.Outlined.CalendarMonth),
    Passkeys(R.string.health_passkeyAvailable, R.string.health_passkeyAvailableHelp, Icons.Outlined.Key),
    Expiring(R.string.health_expiring, R.string.health_expiringHelp, Icons.Outlined.CreditCard),
    BackupCodes(R.string.health_backupCodes, R.string.health_backupCodesHelp, Icons.Outlined.Key),
    EmailBreaches(R.string.health_email_title, R.string.health_email_help, Icons.Outlined.Mail),
    Dismissed(R.string.health_dismissedTitle, R.string.health_dismissedHelp, Icons.Outlined.VisibilityOff);

    fun count(report: HealthReport): Int = when (this) {
        Weak -> report.weak.size
        Reused -> report.reused.sumOf { it.size }
        Breached -> report.breached.size
        TwoStep -> report.missing2fa.size
        RecoveryEmails -> report.recoveryNo2fa.size
        RecoveryBreached -> report.recoveryBreached.size
        Insecure -> report.insecureUrls.size
        Old -> report.old.size
        Passkeys -> report.passkeyAvailable.size
        Expiring -> report.expiring.size
        BackupCodes -> report.lowBackupCodes.size
        EmailBreaches -> report.emailBreaches.size
        Dismissed -> report.dismissed.size
    }
}

/** Health (`HealthPage`): the score, then a tile per check that opens its list. Checked on the phone. */
@Composable
fun HealthScreen() {
    val vault = LocalVault.current
    val model = vault.model
    val report = rememberLive(model) { model.vault.healthReport() }
    val context = LocalContext.current
    VaultPage(
        stringResource(R.string.health_title),
        stringResource(R.string.health_subtitle),
        tag = "health.title",
        actions = {
            IconButton(onClick = report::retry, modifier = Modifier.testTag("health.recheck")) { Icon(Icons.Outlined.Refresh, contentDescription = stringResource(R.string.health_recheck)) }
        },
    ) {
        val data = report.data
        when {
            report.error != null && data == null -> Alert(errorMessage(context, report.error!!))
            data == null -> Loading()
            else -> Overview(data, report::retry)
        }
    }
}

/** One check's list (`HealthCheckPage`), opened from its tile on Health. */
@Composable
fun HealthCheckScreen(check: HealthCheck) {
    val model = LocalVault.current.model
    val report = rememberLive(model) { model.vault.healthReport() }
    val context = LocalContext.current
    val data = report.data
    val help = stringResource(check.help)
    val subtitle = if (check == HealthCheck.RecoveryEmails && data != null) "$help ${pluralStringResource(R.plurals.health_recoveryMapSummary, data.recovery.size, data.recovery.size)}" else help
    VaultPage(stringResource(check.label), subtitle, tag = "health.check.${check.name}") {
        when {
            report.error != null && data == null -> Alert(errorMessage(context, report.error!!))
            data == null -> Loading()
            check == HealthCheck.Dismissed -> DismissedList(data, report::retry)
            else -> CheckList(check, data, report::retry)
        }
    }
}

@Composable
private fun Loading() {
    Column(Modifier.fillMaxWidth().padding(32.dp), horizontalAlignment = Alignment.CenterHorizontally) {
        CircularProgressIndicator()
        Text(stringResource(R.string.health_checking), Modifier.padding(top = 12.dp))
    }
}

/** Whether this account's server checks email addresses, or null while it's asked. */
@Composable
private fun rememberEmailChecksAvailable(): Boolean? {
    val model = LocalVault.current.model
    return rememberLive(model) { runCatching { model.vault.emailBreachChecksAvailable() }.getOrDefault(false) }.data
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun ColumnScope.Overview(report: HealthReport, reload: () -> Unit) {
    val vault = LocalVault.current
    val model = vault.model
    val emailChecks = rememberEmailChecksAvailable() == true
    // Once per visit, so a new breach shows at the top. Sends nothing unless alerts are on and a day has passed.
    LaunchedEffect(report.emailAlertsEnabled) {
        if (report.emailAlertsEnabled && runCatching { model.vault.checkEmailBreaches(false) }.getOrNull() == EmailBreachCheck.CHECKED) reload()
    }
    val score = report.score.toInt()
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(20.dp)) {
        Box(contentAlignment = Alignment.Center) {
            CircularProgressIndicator(progress = { score / 100f }, modifier = Modifier.size(120.dp), strokeWidth = 8.dp, color = healthTone(score), trackColor = MaterialTheme.colorScheme.outlineVariant)
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text(score.toString(), fontSize = 36.sp, fontWeight = FontWeight.Bold, modifier = Modifier.testTag("health.score"))
                Text(stringResource(R.string.health_outOf), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        Column(Modifier.weight(1f)) {
            Text(stringResource(verdict(score)), style = MaterialTheme.typography.titleLarge, modifier = Modifier.semantics { heading() })
            Text(pluralStringResource(R.plurals.health_summary, report.checked.toInt(), report.checked.toInt()), style = MaterialTheme.typography.bodyMedium)
            Text(stringResource(R.string.health_checkedAt, formatDate(report.generatedAt, long = true)), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
    if (!report.breachCheckCompleted) Alert(stringResource(R.string.health_breachUnavailable), AlertTone.Warn)
    if (report.emailBreaches.any { it.isNew }) Alert(stringResource(R.string.health_email_newAlert), AlertTone.Warn)
    app.octap.android.ui.local.LocalBackupLine()

    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        for (check in HealthCheck.entries) {
            val count = check.count(report)
            when {
                check == HealthCheck.Dismissed -> {}
                // Its page is where the switch is, so the tile shows whenever the switch would.
                check == HealthCheck.EmailBreaches -> if (report.emailAlertsEnabled || emailChecks || count > 0) {
                    val on = report.emailAlertsEnabled
                    Tile(check, if (on) count.toString() else stringResource(R.string.health_email_offTile), clear = on && count == 0, off = !on)
                }
                check.always || count > 0 -> Tile(check, count.toString(), clear = count == 0)
            }
        }
    }

    OutlinedCard(Modifier.fillMaxWidth()) {
        Column {
            LinkRow(
                Icons.Outlined.Mail,
                stringResource(R.string.health_recoveryMap),
                pluralStringResource(R.plurals.health_recoveryMapSummary, report.recovery.size, report.recovery.size),
                Modifier.testTag("health.recoveryMap"),
            ) { vault.nav.push(Route.RecoveryMap) }
            if (report.dismissed.isNotEmpty()) {
                HorizontalDivider()
                LinkRow(
                    Icons.Outlined.VisibilityOff,
                    pluralStringResource(R.plurals.health_dismissedCount, report.dismissed.size, report.dismissed.size),
                    stringResource(R.string.health_dismissedNote),
                    Modifier.testTag("health.dismissed"),
                ) { vault.nav.push(Route.HealthCheck(HealthCheck.Dismissed)) }
            }
        }
    }
}

/** A check's count on Health; it opens the check's list. */
@Composable
private fun Tile(check: HealthCheck, value: String, clear: Boolean, off: Boolean = false) {
    val vault = LocalVault.current
    OutlinedCard(onClick = { vault.nav.push(Route.HealthCheck(check)) }, modifier = Modifier.testTag("health.tile.${check.name}")) {
        Row(Modifier.padding(start = 12.dp, end = 6.dp, top = 10.dp, bottom = 10.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            val tint = when {
                clear -> Brand.colors.free
                off -> MaterialTheme.colorScheme.onSurfaceVariant
                else -> Brand.colors.warn
            }
            Icon(if (clear) Icons.Outlined.Check else check.icon, contentDescription = null, tint = tint, modifier = Modifier.size(18.dp))
            Text(value, fontWeight = FontWeight.Bold)
            Text(stringResource(check.label), style = MaterialTheme.typography.bodySmall)
            Icon(Icons.AutoMirrored.Outlined.KeyboardArrowRight, contentDescription = null, tint = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.size(18.dp))
        }
    }
}

@Composable
private fun LinkRow(icon: ImageVector, title: String, subtitle: String, modifier: Modifier = Modifier, onClick: () -> Unit) {
    Row(
        modifier.fillMaxWidth().heightIn(min = 56.dp).clickable(onClick = onClick).padding(horizontal = 16.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Icon(icon, contentDescription = null, tint = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.size(20.dp))
        Column(Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            Text(subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Icon(Icons.AutoMirrored.Outlined.KeyboardArrowRight, null, tint = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

/** What each row can do. Dismissed rows leave at once, ahead of the next report. */
private class RowActions(val hidden: Set<String>, val dismiss: (List<HealthEntry>) -> Unit, val change: (HealthEntry) -> Unit) {
    fun shown(entry: HealthEntry) = entry.warning == null || entry.warning !in hidden
}

@Composable
private fun ColumnScope.CheckList(check: HealthCheck, report: HealthReport, reload: () -> Unit) {
    val vault = LocalVault.current
    val model = vault.model
    val context = LocalContext.current
    var hidden by remember(report) { mutableStateOf(emptySet<String>()) }
    var changing by remember { mutableStateOf<HealthEntry?>(null) }
    // The saves run on the app's scope, so they still finish when Back comes straight after.
    val actions = RowActions(
        hidden,
        dismiss = { entries ->
            val keys = entries.mapNotNull { it.warning }
            hidden = hidden + keys
            model.scope.launch { runCatching { model.vault.dismissHealthWarnings(keys) }.onFailure { hidden = hidden - keys.toSet() } }
        },
        change = { entry ->
            entry.changePasswordUrl?.let { url ->
                try {
                    context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
                } catch (ignored: ActivityNotFoundException) {
                }
            }
            changing = entry
        },
    )
    changing?.let { entry ->
        GeneratorSheet(
            model,
            onUse = { password ->
                changing = null
                model.scope.launch {
                    runCatching { model.vault.updatePassword(entry.itemId, password) }
                    reload()
                }
            },
            onDismiss = { changing = null },
        )
    }

    when (check) {
        HealthCheck.Weak -> {
            val weak = report.weak.filter { actions.shown(it.entry) }
            Rows(weak.isEmpty()) { for (entry in weak) ActionRow(entry.entry, stringResource(strengthLabelRes(entry.score.toInt())), Brand.colors.dangerText, actions, changes = true) }
        }
        HealthCheck.Reused -> {
            val groups = report.reused.filter { group -> group.any(actions::shown) }
            Rows(groups.isEmpty()) {
                groups.forEachIndexed { i, group ->
                    if (i > 0) HorizontalDivider()
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(pluralStringResource(R.plurals.health_reuseGroup, group.size, group.size), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.weight(1f).padding(start = 16.dp, top = 8.dp))
                        TextButton(onClick = { actions.dismiss(group) }) { Text(stringResource(R.string.health_dismissGroup)) }
                    }
                    for (entry in group) ActionRow(entry, null, null, actions, changes = true, dismissible = false)
                }
            }
        }
        HealthCheck.Breached -> {
            if (!report.breachCheckCompleted) Alert(stringResource(R.string.health_breachUnavailable), AlertTone.Warn)
            val breached = report.breached.filter { actions.shown(it.entry) }
            if (report.breachCheckCompleted || breached.isNotEmpty()) {
                Rows(breached.isEmpty()) { for (entry in breached) ActionRow(entry.entry, pluralStringResource(R.plurals.health_seenTimes, entry.count.toInt(), entry.count.toInt()), Brand.colors.dangerText, actions, changes = true) }
            }
        }
        HealthCheck.TwoStep -> {
            val entries = report.missing2fa.filter(actions::shown)
            Rows(entries.isEmpty()) { for (entry in entries) ActionRow(entry, stringResource(R.string.health_supports2fa), Brand.colors.warnText, actions) }
        }
        HealthCheck.RecoveryEmails -> {
            TextButton(onClick = { vault.nav.push(Route.RecoveryMap) }, modifier = Modifier.testTag("health.check.recoveryMap")) { Text(stringResource(R.string.health_viewRecoveryMap)) }
            val entries = report.recoveryNo2fa.filter { actions.shown(it.entry) }
            Rows(entries.isEmpty()) {
                for (entry in entries) ActionRow(entry.entry.copy(subtitle = entry.email), pluralStringResource(R.plurals.health_recoveryResets, entry.accounts.toInt(), entry.accounts.toInt()), Brand.colors.warnText, actions)
            }
        }
        HealthCheck.RecoveryBreached -> {
            val entries = report.recoveryBreached.filter { actions.shown(it.entry) }
            Rows(entries.isEmpty()) {
                for (entry in entries) {
                    val subtitle = "${entry.email} · ${stringResource(R.string.health_recoveryBreachedIn, entry.breaches.joinToString(", "))}"
                    ActionRow(entry.entry.copy(subtitle = subtitle), pluralStringResource(R.plurals.health_recoveryResets, entry.accounts.toInt(), entry.accounts.toInt()), Brand.colors.dangerText, actions)
                }
            }
        }
        HealthCheck.Insecure -> {
            val entries = report.insecureUrls.filter { actions.shown(it.entry) }
            Rows(entries.isEmpty()) { for (entry in entries) ActionRow(entry.entry.copy(subtitle = entry.url), "http://", Brand.colors.warnText, actions) }
        }
        HealthCheck.Old -> {
            val entries = report.old.filter { actions.shown(it.entry) }
            Rows(entries.isEmpty()) { for (entry in entries) ActionRow(entry.entry, stringResource(R.string.health_changedOn, formatDate(entry.changedAt)), null, actions, changes = true) }
        }
        HealthCheck.Passkeys -> {
            val entries = report.passkeyAvailable.filter(actions::shown)
            Rows(entries.isEmpty()) { for (entry in entries) ActionRow(entry, stringResource(R.string.health_supportsPasskeys), null, actions) }
        }
        HealthCheck.Expiring -> {
            val entries = report.expiring.filter { actions.shown(it.entry) }
            Rows(entries.isEmpty()) {
                for (entry in entries) {
                    val left = entry.daysLeft
                    val tag = when {
                        left < 0 -> stringResource(R.string.health_expired)
                        left == 0 -> stringResource(R.string.health_expiresToday)
                        else -> pluralStringResource(R.plurals.health_expiresIn, left, left)
                    }
                    ActionRow(entry.entry, tag, if (left < 0) Brand.colors.dangerText else Brand.colors.warnText, actions)
                }
            }
        }
        HealthCheck.BackupCodes -> {
            val entries = report.lowBackupCodes.filter { actions.shown(it.entry) }
            Rows(entries.isEmpty()) { for (entry in entries) ActionRow(entry.entry, pluralStringResource(R.plurals.health_codesLeft, entry.unused.toInt(), entry.unused.toInt()), Brand.colors.warnText, actions) }
        }
        HealthCheck.EmailBreaches -> EmailAlerts(report, hidden, reload) { key ->
            hidden = hidden + key
            model.scope.launch { runCatching { model.vault.dismissHealthWarnings(listOf(key)) } }
        }
        HealthCheck.Dismissed -> {}
    }
}

/** Warnings the user dismissed. They don't count towards the score until shown again. */
@Composable
private fun DismissedList(report: HealthReport, reload: () -> Unit) {
    val model = LocalVault.current.model
    Rows(report.dismissed.isEmpty()) {
        for (item in report.dismissed) {
            Row(Modifier.fillMaxWidth().padding(start = 16.dp), verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(item.entry.title, style = MaterialTheme.typography.bodyLarge)
                    Text(stringResource(checkLabel(item.check)), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                TextButton(
                    onClick = {
                        model.scope.launch {
                            runCatching { model.vault.restoreHealthWarnings(listOf(item.warning)) }
                            reload()
                        }
                    },
                    modifier = Modifier.testTag("health.restore.${item.warning}"),
                ) { Text(stringResource(R.string.health_restore)) }
            }
        }
    }
}

private fun checkLabel(check: String) = when (check) {
    "weak" -> R.string.health_weak
    "reused" -> R.string.health_reused
    "breached" -> R.string.health_breached
    "old" -> R.string.health_old
    "missing2fa" -> R.string.health_missing2fa
    "passkeyAvailable" -> R.string.health_passkeyAvailable
    "insecureUrl" -> R.string.health_insecureUrls
    "expiring" -> R.string.health_expiring
    "backupCodes" -> R.string.health_backupCodes
    "recoveryNo2fa" -> R.string.health_recoveryNo2fa
    "recoveryBreached" -> R.string.health_recoveryBreached
    else -> R.string.health_email_title
}

/** A warning's row with what can be done about it. */
@Composable
private fun ActionRow(entry: HealthEntry, tag: String?, tone: Color?, actions: RowActions, changes: Boolean = false, dismissible: Boolean = true) {
    Column {
        EntryRow(entry, tag, tone)
        Row(Modifier.fillMaxWidth().padding(end = 8.dp), horizontalArrangement = Arrangement.End) {
            if (changes) TextButton(onClick = { actions.change(entry) }, modifier = Modifier.testTag("health.change.${entry.itemId}")) { Text(stringResource(R.string.health_change_action)) }
            if (dismissible) TextButton(onClick = { actions.dismiss(listOf(entry)) }, modifier = Modifier.testTag("health.dismiss.${entry.itemId}")) { Text(stringResource(R.string.health_dismiss)) }
        }
    }
}

/**
 * The email breach alerts page's body; its title and help are the page's. Off by default. Turning
 * it on sends addresses off the phone, so it asks first and says so.
 */
@Composable
private fun EmailAlerts(report: HealthReport, hidden: Set<String>, reload: () -> Unit, dismiss: (String) -> Unit) {
    val model = LocalVault.current.model
    val available = rememberEmailChecksAvailable()
    var confirming by remember { mutableStateOf(false) }
    var confirmingRecovery by remember { mutableStateOf(false) }
    var check by remember { mutableStateOf<EmailBreachCheck?>(null) }
    val run: (Boolean) -> Unit = { force ->
        model.scope.launch {
            val result = runCatching { model.vault.checkEmailBreaches(force) }.getOrDefault(EmailBreachCheck.FAILED)
            check = result
            if (result == EmailBreachCheck.CHECKED) reload()
        }
    }
    if (!report.emailAlertsEnabled && available != true) {
        if (available == false) Alert(stringResource(R.string.health_email_unavailable), AlertTone.Info)
        return
    }
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(stringResource(R.string.health_email_switch), style = MaterialTheme.typography.bodyLarge)
                Text(stringResource(if (report.emailAlertsEnabled) R.string.health_email_onNote else R.string.health_email_offNote), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Switch(
                checked = report.emailAlertsEnabled,
                modifier = Modifier.testTag("health.emailAlerts"),
                onCheckedChange = { on ->
                    if (on) {
                        confirming = true
                    } else {
                        model.scope.launch {
                            runCatching { model.vault.setEmailBreachAlerts(false) }
                            reload()
                        }
                    }
                },
            )
        }
        if (report.emailAlertsEnabled) {
            // The second opt-in: recovery emails that are neither the account email nor an alias.
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(stringResource(R.string.health_email_recoverySwitch), style = MaterialTheme.typography.bodyLarge)
                    Text(stringResource(if (report.emailAlertsRecoveryEmails) R.string.health_email_recoveryOnNote else R.string.health_email_recoveryOffNote), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                Switch(
                    checked = report.emailAlertsRecoveryEmails,
                    modifier = Modifier.testTag("health.emailAlerts.recoveryEmails"),
                    onCheckedChange = { on ->
                        if (on) {
                            confirmingRecovery = true
                        } else {
                            model.scope.launch {
                                runCatching { model.vault.setRecoveryEmailChecks(false) }
                                run(true)
                                reload()
                            }
                        }
                    },
                )
            }
            if (check == EmailBreachCheck.FAILED) Alert(stringResource(R.string.health_email_failed), AlertTone.Warn)
            TextButton(onClick = { run(true) }) { Text(stringResource(R.string.health_email_checkNow)) }
            val findings = report.emailBreaches.filter { it.warning !in hidden }
            if (findings.isNotEmpty()) {
                OutlinedCard(Modifier.fillMaxWidth()) { Column { for (finding in findings) BreachRow(finding) { dismiss(finding.warning) } } }
            } else if (report.emailBreachesCheckedAt != null) {
                Text(stringResource(R.string.health_email_none), color = Brand.colors.freeText)
            }
            Text("${stringResource(R.string.health_email_source)} Have I Been Pwned", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
    if (confirming) {
        AlertDialog(
            onDismissRequest = { confirming = false },
            title = { Text(stringResource(R.string.health_email_confirmTitle)) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(stringResource(R.string.health_email_sendsAddresses))
                    Text(stringResource(R.string.health_email_sendsTo))
                    Text(stringResource(R.string.health_email_aliasNote))
                    Text(stringResource(R.string.health_email_notStored))
                }
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        confirming = false
                        model.scope.launch {
                            runCatching { model.vault.setEmailBreachAlerts(true) }
                            run(true)
                            reload()
                        }
                    },
                    modifier = Modifier.testTag("health.emailAlerts.confirm"),
                ) { Text(stringResource(R.string.health_email_confirm)) }
            },
            dismissButton = { TextButton(onClick = { confirming = false }) { Text(stringResource(R.string.common_cancel)) } },
        )
    }
    if (confirmingRecovery) {
        AlertDialog(
            onDismissRequest = { confirmingRecovery = false },
            title = { Text(stringResource(R.string.health_email_recoveryConfirmTitle)) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(stringResource(R.string.health_email_recoverySends))
                    Text(stringResource(R.string.health_email_recoveryNotYours))
                    Text(stringResource(R.string.health_email_notStored))
                    Text(stringResource(R.string.health_email_recoveryForgets))
                }
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        confirmingRecovery = false
                        model.scope.launch {
                            runCatching { model.vault.setRecoveryEmailChecks(true) }
                            run(true)
                            reload()
                        }
                    },
                    modifier = Modifier.testTag("health.emailAlerts.recoveryEmails.confirm"),
                ) { Text(stringResource(R.string.health_email_recoveryConfirm)) }
            },
            dismissButton = { TextButton(onClick = { confirmingRecovery = false }) { Text(stringResource(R.string.common_cancel)) } },
        )
    }
}

@Composable
private fun BreachRow(finding: EmailBreachFinding, dismiss: () -> Unit) {
    Row(Modifier.fillMaxWidth().padding(start = 16.dp, top = 8.dp, bottom = 8.dp), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(finding.title, style = MaterialTheme.typography.bodyLarge)
                if (finding.isNew) Text(stringResource(R.string.health_email_new), style = MaterialTheme.typography.labelSmall, color = Brand.colors.dangerText)
            }
            Text(finding.address, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            if (finding.dataClasses.isNotEmpty()) Text(finding.dataClasses.joinToString(", "), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        TextButton(onClick = dismiss) { Text(stringResource(R.string.health_dismiss)) }
    }
}

/** A check's rows, or "None found." once there's nothing left to fix. */
@Composable
private fun Rows(empty: Boolean, rows: @Composable () -> Unit) {
    if (empty) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            Icon(Icons.Outlined.Check, null, tint = Brand.colors.free, modifier = Modifier.size(18.dp))
            Text(stringResource(R.string.health_noneFound), color = Brand.colors.freeText)
        }
    } else {
        OutlinedCard(Modifier.fillMaxWidth()) { Column { rows() } }
    }
}

/** A login in a health list; it opens the item (`Row`). A warning about an address with no login opens nothing. */
@Composable
fun EntryRow(entry: HealthEntry, tag: String? = null, tone: Color? = null) {
    val vault = LocalVault.current
    val opens = if (entry.itemId.isEmpty()) Modifier else Modifier.clickable { vault.nav.push(Route.Item(entry.itemId)) }
    Row(
        Modifier.fillMaxWidth().heightIn(min = 56.dp).then(opens).padding(horizontal = 16.dp, vertical = 8.dp).testTag("health.entry.${entry.itemId.ifEmpty { entry.title }}"),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Avatar(entry.title, 32.dp)
        Column(Modifier.weight(1f)) {
            Text(entry.title, style = MaterialTheme.typography.bodyLarge)
            entry.subtitle?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
        }
        if (tag != null) Text(tag, style = MaterialTheme.typography.labelSmall, color = tone ?: MaterialTheme.colorScheme.onSurfaceVariant)
        if (entry.itemId.isNotEmpty()) Icon(Icons.AutoMirrored.Outlined.KeyboardArrowRight, null, tint = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

/** The recovery map (`RecoveryMapPage`, plan 01): which email or phone can reset which logins. */
@Composable
fun RecoveryMapScreen() {
    val model = LocalVault.current.model
    val report = rememberLive(model) { model.vault.healthReport() }
    val context = LocalContext.current
    VaultPage(stringResource(R.string.recoveryMap_title), stringResource(R.string.recoveryMap_subtitle), tag = "recoveryMap.title") {
        val data = report.data
        when {
            report.error != null && data == null -> Alert(errorMessage(context, report.error!!))
            data == null -> CircularProgressIndicator(Modifier.align(Alignment.CenterHorizontally))
            data.recovery.isEmpty() -> Box(Modifier.heightIn(min = 320.dp)) { Empty(Icons.Outlined.Mail, stringResource(R.string.recoveryMap_empty), stringResource(R.string.recoveryMap_emptyBody)) }
            else -> {
                Text(stringResource(R.string.recoveryMap_help), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                for (contact in data.recovery) Contact(contact)
                Alert(stringResource(R.string.recoveryMap_breachGap), AlertTone.Info)
            }
        }
    }
}

@Composable
private fun Contact(contact: RecoveryContact) {
    val vault = LocalVault.current
    Column(Modifier.padding(top = 8.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Icon(if (contact.kind == RecoveryKind.EMAIL) Icons.Outlined.Mail else Icons.Outlined.Phone, null, Modifier.size(20.dp))
            Text(pluralStringResource(R.plurals.recoveryMap_canReset, contact.logins.size, contact.logins.size, contact.value), style = MaterialTheme.typography.titleSmall, modifier = Modifier.semantics { heading() })
        }
        val account = contact.account
        when {
            contact.aliasProvider != null -> Text(stringResource(R.string.recoveryMap_masked, providerName(contact.aliasProvider)), style = MaterialTheme.typography.labelMedium)
            contact.kind == RecoveryKind.EMAIL && account != null -> Text(
                stringResource(if (account.twoStep) R.string.recoveryMap_accountTwoStep else R.string.recoveryMap_accountNoTwoStep),
                style = MaterialTheme.typography.labelMedium,
                color = if (account.twoStep) Brand.colors.trustText else Brand.colors.warnText,
                modifier = Modifier.clickable { vault.nav.push(Route.Item(account.entry.itemId)) },
            )
            contact.kind == RecoveryKind.EMAIL -> Text(stringResource(R.string.recoveryMap_accountMissing), style = MaterialTheme.typography.labelMedium)
        }
        contact.identityId?.let { id ->
            Text(stringResource(R.string.recoveryMap_fromIdentity), style = MaterialTheme.typography.labelMedium, color = Brand.colors.trustText, modifier = Modifier.clickable { vault.nav.push(Route.Item(id)) })
        }
        OutlinedCard(Modifier.fillMaxWidth()) { Column { for (entry in contact.logins) EntryRow(entry) } }
    }
}
