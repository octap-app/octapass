package app.octap.android.ui.components

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import app.octap.android.platform.Qr

/** A QR code, black on white in both themes so every camera reads it. */
@Composable
fun QrImage(text: String, size: Dp, label: String, modifier: Modifier = Modifier) {
    val modules = remember(text) { Qr.encode(text, margin = 0) }
    Canvas(
        modifier
            .background(Color.White)
            .padding(size / 14)
            .size(size)
            .semantics { contentDescription = label },
    ) {
        val cell = this.size.width / modules.width
        for (row in 0 until modules.height) for (col in 0 until modules.width) {
            if (modules[col, row]) drawRect(Color.Black, Offset(col * cell, row * cell), Size(cell + 0.5f, cell + 0.5f))
        }
    }
}

val QrDefaultSize = 124.dp
