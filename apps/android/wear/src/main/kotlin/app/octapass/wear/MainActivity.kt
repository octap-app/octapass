package app.octap.wear

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.repeatOnLifecycle
import androidx.wear.compose.foundation.lazy.ScalingLazyColumn
import androidx.wear.compose.foundation.lazy.items
import androidx.wear.compose.foundation.lazy.rememberScalingLazyListState
import androidx.wear.compose.material3.AppScaffold
import androidx.wear.compose.material3.Button
import androidx.wear.compose.material3.ButtonDefaults
import androidx.wear.compose.material3.MaterialTheme
import androidx.wear.compose.material3.ScreenScaffold
import androidx.wear.compose.material3.Text
import app.octap.resources.R
import app.octap.resources.Tokens
import kotlinx.coroutines.delay

/** The brand tokens' dark values: a watch is always dark. */
private object Palette {
    val ink = Color(Tokens.DarkColors.ink)
    val mist = Color(Tokens.DarkColors.mist)
    val line = Color(Tokens.DarkColors.line)
    val free = Color(Tokens.DarkColors.free)
    val warn = Color(Tokens.DarkColors.warn)

    /** Buttons are always the light trust blue with white text (brand/README.md). */
    val button = Color(Tokens.LightColors.button)
}

/** The Wear OS app: one list of the one-time codes the phone sent. */
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // No screenshots of codes.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        setContent { MaterialTheme { AppScaffold { CodesScreen() } } }
    }
}

@Composable
private fun CodesScreen() {
    val context = LocalContext.current
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    val codes by CodeStore.codes.collectAsStateWithLifecycle()
    var nowMs by remember { mutableLongStateOf(System.currentTimeMillis()) }
    var secure by remember { mutableStateOf(context.hasScreenLock()) }

    // Each time the app comes up: check the lock, ask the phone, then tick while it's on screen.
    LaunchedEffect(lifecycle) {
        lifecycle.repeatOnLifecycle(Lifecycle.State.RESUMED) {
            secure = context.hasScreenLock()
            if (secure) PhoneRequests.askForCodes(context) else CodeStore.forgetAll()
            while (true) {
                nowMs = System.currentTimeMillis()
                CodeStore.forgetExpired()
                delay(1000 - nowMs % 1000)
            }
        }
    }

    val rows = codes.rows(nowMs)
    when {
        !secure -> Message(stringResource(R.string.phone_native_watchNoLock), stringResource(R.string.phone_native_watchNoLockHelpAndroid))
        rows.isNotEmpty() -> CodeList(rows)
        codes.isEmptyVault(nowMs) -> Message(stringResource(R.string.phone_native_watchNoCodes), null)
        else -> Message(stringResource(R.string.phone_native_watchEmptyAndroid), stringResource(R.string.phone_native_watchEmptyHelp)) {
            PhoneRequests.askForCodes(context)
        }
    }
}

@Composable
private fun CodeList(rows: List<Pair<WatchEntry, WatchCode>>) {
    val state = rememberScalingLazyListState()
    ScreenScaffold(scrollState = state) { padding ->
        ScalingLazyColumn(state = state, contentPadding = padding, modifier = Modifier.fillMaxWidth()) {
            items(rows, key = { it.first.id }) { (entry, code) -> CodeRow(entry.title, code) }
        }
    }
}

@Composable
private fun CodeRow(title: String, code: WatchCode) {
    val shownTitle = title.ifEmpty { stringResource(R.string.otp_untitled) }
    val spoken = stringResource(R.string.phone_native_watchCodeLabel, shownTitle, code.text.toList().joinToString(" "))
    val left = pluralStringResource(R.plurals.phone_native_watchCodeExpiresIn, code.remainingSeconds, code.remainingSeconds)
    Row(
        Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 4.dp).clearAndSetSemantics { contentDescription = "$spoken. $left" },
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Column(Modifier.weight(1f)) {
            Text(shownTitle, color = Palette.mist, fontSize = 13.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
            // A code reads left to right in every language.
            CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
                Text(code.display, color = Palette.ink, fontSize = 20.sp, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.SemiBold, maxLines = 1)
            }
        }
        Countdown(code)
    }
}

@Composable
private fun Countdown(code: WatchCode) {
    val color = if (code.remainingSeconds <= 5) Palette.warn else Palette.free
    Box(Modifier.size(28.dp), contentAlignment = Alignment.Center) {
        Canvas(Modifier.size(28.dp)) {
            val width = 3.dp.toPx()
            val inset = width / 2
            val arc = Size(size.width - width, size.height - width)
            drawArc(Palette.line, 0f, 360f, false, Offset(inset, inset), arc, style = Stroke(width))
            drawArc(color, -90f, 360f * code.fraction, false, Offset(inset, inset), arc, style = Stroke(width, cap = StrokeCap.Round))
        }
        Text("${code.remainingSeconds}", color = Palette.mist, fontSize = 11.sp)
    }
}

@Composable
private fun Message(title: String, help: String?, refresh: (() -> Unit)? = null) {
    val state = rememberScalingLazyListState()
    ScreenScaffold(scrollState = state) { padding ->
        ScalingLazyColumn(state = state, contentPadding = padding, modifier = Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
            item { Text(title, color = Palette.ink, fontWeight = FontWeight.SemiBold, textAlign = TextAlign.Center) }
            if (help != null) item { Text(help, color = Palette.mist, fontSize = 13.sp, textAlign = TextAlign.Center) }
            if (refresh != null) {
                item {
                    Button(
                        onClick = refresh,
                        colors = ButtonDefaults.buttonColors(containerColor = Palette.button, contentColor = Color.White),
                    ) { Text(stringResource(R.string.phone_native_watchRefresh)) }
                }
            }
        }
    }
}
