package app.octap.android.autofill

import android.content.Context
import android.content.pm.PackageManager

/** What to call a login saved for an app: the core names new logins only after websites. */
object AppNames {
    /** The app's name when Android lets Octa Pass see the app, else its package name. */
    fun label(context: Context, packageName: String): String = try {
        val info = context.packageManager.getApplicationInfo(packageName, 0)
        context.packageManager.getApplicationLabel(info).toString().ifBlank { packageName }
    } catch (error: PackageManager.NameNotFoundException) {
        packageName
    }
}
