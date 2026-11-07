package app.octap.android.platform

import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.EncodeHintType
import com.google.zxing.NotFoundException
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.ReaderException
import com.google.zxing.common.BitMatrix
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel

/** QR codes made and read on the phone (ZXing); nothing is sent anywhere. */
object Qr {
    private val hints = mapOf(
        DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),
        DecodeHintType.TRY_HARDER to true,
    )

    /** The modules of [text]'s code, with a quiet zone of [margin] modules. */
    fun encode(text: String, margin: Int = 2): BitMatrix =
        QRCodeWriter().encode(
            text,
            BarcodeFormat.QR_CODE,
            0,
            0,
            mapOf(EncodeHintType.MARGIN to margin, EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M, EncodeHintType.CHARACTER_SET to "UTF-8"),
        )

    /** A code in a camera frame's luminance (Y) plane, or null. [rowStride] is the plane's bytes per row. */
    fun decodeFrame(luminance: ByteArray, rowStride: Int, width: Int, height: Int): String? =
        decode(PlanarYUVLuminanceSource(luminance, rowStride, height, 0, 0, width, height, false))

    /** A code in a picture's ARGB pixels (a photo or a screenshot), or null. */
    fun decodePixels(pixels: IntArray, width: Int, height: Int): String? = decode(RGBLuminanceSource(width, height, pixels))

    private fun decode(source: com.google.zxing.LuminanceSource): String? = try {
        QRCodeReader().decode(BinaryBitmap(HybridBinarizer(source)), hints).text
    } catch (error: NotFoundException) {
        null
    } catch (error: ReaderException) {
        null
    }
}
