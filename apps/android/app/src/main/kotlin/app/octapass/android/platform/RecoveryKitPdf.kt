package app.octap.android.platform

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.RectF
import android.graphics.Typeface
import android.graphics.pdf.PdfDocument
import android.net.Uri
import android.os.Bundle
import android.os.CancellationSignal
import android.os.ParcelFileDescriptor
import android.print.PageRange
import android.print.PrintAttributes
import android.print.PrintDocumentAdapter
import android.print.PrintDocumentInfo
import android.text.Layout
import android.text.StaticLayout
import android.text.TextPaint
import app.octap.resources.R
import app.octap.vault.NewRecoveryKit
import java.io.File
import java.io.FileOutputStream
import java.io.OutputStream
import java.net.URLEncoder
import java.text.DateFormat
import java.time.Instant
import java.util.Date

/**
 * The Recovery Kit as a one-page PDF (`RecoveryKitSheet`), drawn on the phone: email, server,
 * Secret Key, a blank for the master password, the setup QR code and the recovery code. It's
 * printed, saved where the user picks or handed to the share sheet; a shared copy is deleted when
 * the sheet closes. Nothing is uploaded.
 */
object RecoveryKitPdf {
    /** What a new device scans to fill in the email, server and Secret Key. Never the recovery code. */
    fun setupUri(kit: NewRecoveryKit): String {
        fun enc(value: String) = URLEncoder.encode(value, "UTF-8")
        return "octapass://setup?email=${enc(kit.email)}&server=${enc(kit.serverUrl)}&secretKey=${enc(kit.secretKey)}"
    }

    fun write(context: Context, kit: NewRecoveryKit, out: OutputStream) {
        val document = PdfDocument()
        val page = document.startPage(PdfDocument.PageInfo.Builder(WIDTH, HEIGHT, 1).create())
        draw(context, kit, page.canvas)
        document.finishPage(page)
        document.writeTo(out)
        document.close()
    }

    /** A copy in the app's cache for the share sheet. */
    fun file(context: Context, kit: NewRecoveryKit): File {
        val folder = File(context.cacheDir, "share-${System.nanoTime()}").apply { mkdirs() }
        val file = File(folder, fileName(context))
        FileOutputStream(file).use { write(context, kit, it) }
        return file
    }

    fun fileName(context: Context) = "${context.getString(R.string.kit_sheetTitle)}.pdf"

    fun save(context: Context, kit: NewRecoveryKit, uri: Uri) {
        context.contentResolver.openOutputStream(uri, "wt")?.use { write(context, kit, it) } ?: error("couldn't write the file")
    }

    fun printAdapter(context: Context, kit: NewRecoveryKit) = object : PrintDocumentAdapter() {
        override fun onLayout(old: PrintAttributes?, new: PrintAttributes, cancel: CancellationSignal, callback: LayoutResultCallback, extras: Bundle?) {
            if (cancel.isCanceled) return callback.onLayoutCancelled()
            callback.onLayoutFinished(
                PrintDocumentInfo.Builder(fileName(context)).setContentType(PrintDocumentInfo.CONTENT_TYPE_DOCUMENT).setPageCount(1).build(),
                old != new,
            )
        }

        override fun onWrite(pages: Array<out PageRange>, destination: ParcelFileDescriptor, cancel: CancellationSignal, callback: WriteResultCallback) {
            try {
                FileOutputStream(destination.fileDescriptor).use { write(context, kit, it) }
                callback.onWriteFinished(arrayOf(PageRange.ALL_PAGES))
            } catch (error: Exception) {
                callback.onWriteFailed(error.message)
            }
        }
    }

    // A4 in PostScript points.
    private const val WIDTH = 595
    private const val HEIGHT = 842
    private const val MARGIN = 56f

    private fun draw(context: Context, kit: NewRecoveryKit, canvas: Canvas) {
        val ink = Color.rgb(0x0b, 0x12, 0x20)
        val mist = Color.rgb(0x5e, 0x65, 0x76)
        val title = TextPaint(Paint.ANTI_ALIAS_FLAG).apply { color = ink; textSize = 22f; typeface = Typeface.DEFAULT_BOLD }
        val label = TextPaint(Paint.ANTI_ALIAS_FLAG).apply { color = mist; textSize = 10f }
        val value = TextPaint(Paint.ANTI_ALIAS_FLAG).apply { color = ink; textSize = 13f }
        val mono = TextPaint(Paint.ANTI_ALIAS_FLAG).apply { color = ink; textSize = 14f; typeface = Typeface.MONOSPACE }
        val small = TextPaint(Paint.ANTI_ALIAS_FLAG).apply { color = mist; textSize = 10f }
        val width = (WIDTH - 2 * MARGIN).toInt()
        var y = MARGIN

        fun text(content: String, paint: TextPaint, w: Int = width, x: Float = MARGIN): Float {
            val layout = StaticLayout.Builder.obtain(content, 0, content.length, paint, w).setAlignment(Layout.Alignment.ALIGN_NORMAL).build()
            canvas.save()
            canvas.translate(x, y)
            layout.draw(canvas)
            canvas.restore()
            return layout.height.toFloat()
        }

        y += text(context.getString(R.string.kit_sheetTitle), title) + 4
        val created = runCatching { DateFormat.getDateInstance(DateFormat.LONG).format(Date.from(Instant.parse(kit.createdAt))) }.getOrDefault(kit.createdAt)
        y += text(context.getString(R.string.kit_createdOn, created), label) + 24

        for ((name, content, paint) in listOf(
            Triple(R.string.fields_email, kit.email, value),
            Triple(R.string.kit_server, kit.serverUrl, value),
            Triple(R.string.fields_secretKey, kit.secretKey, mono),
        )) {
            y += text(context.getString(name), label) + 2
            y += text(content, paint) + 14
        }
        y += text(context.getString(R.string.fields_masterPassword), label) + 22
        canvas.drawLine(MARGIN, y, WIDTH - MARGIN, y, Paint().apply { color = mist; strokeWidth = 0.7f })
        y += 28

        val modules = Qr.encode(setupUri(kit), margin = 0)
        val size = 120f
        val cell = size / modules.width
        val dark = Paint().apply { color = Color.BLACK }
        for (row in 0 until modules.height) for (col in 0 until modules.width) {
            if (modules[col, row]) canvas.drawRect(RectF(MARGIN + col * cell, y + row * cell, MARGIN + (col + 1) * cell, y + (row + 1) * cell), dark)
        }
        val help = y
        y = help + 4
        text(context.getString(R.string.kit_qrHelp), small, width - size.toInt() - 20, MARGIN + size + 20)
        y = help + size + 28

        y += text(context.getString(R.string.kit_recoveryCode), title.apply { textSize = 15f }) + 6
        // Without one, the previous kit's recovery code still works.
        y += (kit.recoveryCode?.let { text(it, mono) } ?: text(context.getString(R.string.kit_recoveryKept), value)) + 6
        y += text(context.getString(R.string.kit_recoveryHelp), small) + 24
        text(context.getString(R.string.kit_keepSafe), small)
    }
}
