package app.octap.jetbrains

import com.intellij.DynamicBundle
import org.jetbrains.annotations.PropertyKey

private const val BUNDLE = "messages.OctaPassBundle"

private object OctaPassBundle : DynamicBundle(BUNDLE)

fun message(@PropertyKey(resourceBundle = BUNDLE) key: String, vararg params: Any): String =
    OctaPassBundle.getMessage(key, *params)
