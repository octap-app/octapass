package app.octap.android.ui.tools

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts.RequestPermission
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import app.octap.android.platform.Qr
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/** What the camera can do here. */
enum class CameraState { Asking, Ready, Unavailable }

/**
 * The camera's picture with QR codes read on the phone (CameraX frames, decoded with ZXing, as the
 * Tauri app's scanner did). [onCode] gets each new code's text once; nothing is sent anywhere.
 */
@Composable
fun QrCamera(label: String, onState: (CameraState) -> Unit, onCode: (String) -> Unit, modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val lifecycle = LocalLifecycleOwner.current
    val found by rememberUpdatedState(onCode)
    val state by rememberUpdatedState(onState)
    var granted by remember { mutableStateOf(ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) }
    val hasCamera = remember { context.packageManager.hasSystemFeature(PackageManager.FEATURE_CAMERA_ANY) }
    val ask = rememberLauncherForActivityResult(RequestPermission()) { ok ->
        granted = ok
        state(if (ok) CameraState.Ready else CameraState.Unavailable)
    }
    LaunchedEffect(Unit) {
        when {
            !hasCamera -> state(CameraState.Unavailable)
            granted -> state(CameraState.Ready)
            else -> {
                state(CameraState.Asking)
                ask.launch(Manifest.permission.CAMERA)
            }
        }
    }
    if (!granted || !hasCamera) {
        Box(modifier.fillMaxSize())
        return
    }
    val preview = remember { PreviewView(context) }
    val analysis = remember { Executors.newSingleThreadExecutor() }
    // The same code stays in view for a while: report each text once.
    val seen = remember { mutableSetOf<String>() }
    val busy = remember { AtomicBoolean(false) }
    DisposableEffect(lifecycle) {
        val future = ProcessCameraProvider.getInstance(context)
        future.addListener({
            val provider = future.get()
            val shown = Preview.Builder().build().also { it.surfaceProvider = preview.surfaceProvider }
            val frames = ImageAnalysis.Builder()
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .build()
                .also { frames ->
                    frames.setAnalyzer(analysis) { image: ImageProxy ->
                        image.use {
                            if (busy.get()) return@use
                            val plane = it.planes[0]
                            val bytes = ByteArray(plane.buffer.remaining()).also { b -> plane.buffer.get(b) }
                            val text = Qr.decodeFrame(bytes, plane.rowStride, it.width, it.height) ?: return@use
                            ContextCompat.getMainExecutor(context).execute {
                                if (seen.add(text)) found(text)
                            }
                        }
                    }
                }
            try {
                provider.unbindAll()
                provider.bindToLifecycle(lifecycle, CameraSelector.DEFAULT_BACK_CAMERA, shown, frames)
            } catch (error: IllegalArgumentException) {
                state(CameraState.Unavailable)
            }
        }, ContextCompat.getMainExecutor(context))
        onDispose {
            runCatching { ProcessCameraProvider.getInstance(context).get().unbindAll() }
            analysis.shutdown()
        }
    }
    AndroidView({ preview }, modifier.fillMaxSize().semantics { contentDescription = label })
}
