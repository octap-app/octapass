package app.octap.android.ui.local

import androidx.annotation.StringRes
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import app.octap.android.model.LocalFlow
import app.octap.android.ui.components.PrimaryButton
import app.octap.android.ui.tools.VaultPage
import app.octap.android.ui.vault.LocalVault
import app.octap.resources.R

/** What only an account can do. A local vault shows [title] and this in its place, never a dead end (plan 05). */
@Composable
fun AccountOnly(@StringRes title: Int, content: @Composable () -> Unit) {
    if (LocalVault.current.model.isLocal) NeedsSyncScreen(title) else content()
}

@Composable
private fun NeedsSyncScreen(@StringRes title: Int) {
    val model = LocalVault.current.model
    VaultPage(stringResource(title), tag = "needsSync.title") {
        Column(
            Modifier.fillMaxWidth().padding(vertical = 32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Icon(Icons.Outlined.Refresh, contentDescription = null, tint = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.size(28.dp))
            Text(stringResource(R.string.localVault_needsSync), style = MaterialTheme.typography.titleLarge, textAlign = TextAlign.Center, modifier = Modifier.semantics { heading() })
            Text(stringResource(R.string.localVault_needsSyncBody), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, textAlign = TextAlign.Center)
            PrimaryButton(
                stringResource(R.string.localVault_turnOnSync),
                { model.localFlow.value = LocalFlow.TurnOnSync },
                icon = Icons.Outlined.Refresh,
                modifier = Modifier.testTag("needsSync.turnOn"),
            )
        }
    }
}
