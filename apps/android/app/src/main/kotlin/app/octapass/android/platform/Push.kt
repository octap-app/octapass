package app.octap.android.platform

import android.Manifest
import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import androidx.core.content.edit
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import app.octap.android.BuildConfig
import app.octap.android.MainActivity
import app.octap.android.OctaPassApp
import app.octap.android.model.AppModel
import app.octap.android.model.isLocal
import app.octap.android.R as AppR
import app.octap.resources.R
import app.octap.vault.OctaPassVault
import app.octap.vault.PushPlatform
import app.octap.vault.SessionStatus
import com.google.android.gms.tasks.Tasks
import com.google.firebase.FirebaseApp
import com.google.firebase.FirebaseOptions
import com.google.firebase.messaging.FirebaseMessaging
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull

/** The Firebase project the push relay sends through: the build's `-PoctapassFcm…` properties. */
data class FcmConfig(val projectId: String, val appId: String, val apiKey: String, val senderId: String) {
    fun options(): FirebaseOptions = FirebaseOptions.Builder()
        .setProjectId(projectId)
        .setApplicationId(appId)
        .setApiKey(apiKey)
        .setGcmSenderId(senderId)
        .build()

    companion object {
        /** Null unless all four are set: a build without them has no push and never starts Firebase. */
        fun of(projectId: String, appId: String, apiKey: String, senderId: String): FcmConfig? {
            val values = listOf(projectId, appId, apiKey, senderId).map { it.trim() }
            if (values.any { it.isEmpty() }) return null
            return FcmConfig(values[0], values[1], values[2], values[3])
        }

        val build: FcmConfig? = of(BuildConfig.FCM_PROJECT_ID, BuildConfig.FCM_APP_ID, BuildConfig.FCM_API_KEY, BuildConfig.FCM_SENDER_ID)
    }
}

/** What a push says. The relay's pushes carry this and nothing else (plan 04, "Push relay"). */
enum class PushKind {
    /** Something in the account changed: sync. */
    Sync,

    /** Sharing, a family invite or emergency access: a notification with the generic words, and a sync. */
    Alert;

    companion object {
        /**
         * The kind in a push's data, or null for a push that isn't the relay's. A kind this version
         * doesn't know (a newer relay) still syncs, which is always safe.
         */
        fun of(data: Map<String, String>): PushKind? = when (data["octapass"] ?: return null) {
            "alert" -> Alert
            else -> Sync
        }
    }
}

private const val ALERT_CHANNEL = "alerts"
private const val ALERT_NOTIFICATION = 1

/** A push service gives a message about 20 seconds; the sync gets most of them. */
private const val PUSH_SYNC_TIMEOUT_MS = 15_000L

/**
 * Push sync on Android: Firebase Cloud Messaging, started by hand from [FcmConfig] (no
 * google-services.json, no other Firebase product), hands its token to the vault, which sends it
 * to the account's server. Without the build's FCM values, or without Google Play services,
 * there's no token and the app syncs as it always did: on opening and while open.
 */
class PushLink(private val app: Application, private val vault: OctaPassVault) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    /** This build can get pushes: Firebase was started. */
    @Volatile
    var available = false
        private set

    /** At every launch: Firebase gives the token again, and the vault remembers it in memory only. */
    fun start(config: FcmConfig? = FcmConfig.build) {
        config ?: return
        available = runCatching {
            if (FirebaseApp.getApps(app).isEmpty()) FirebaseApp.initializeApp(app, config.options())
        }.isSuccess
        if (!available) return
        createChannel()
        scope.launch {
            // Fails without Google Play services, or offline; the next launch asks again.
            // firebase-messaging 26 deprecates getToken/onNewToken for register/onRegistered,
            // which needs `firebase_messaging_installation_id_enabled` turned on; the token API
            // stays the library's default, so Octa Pass keeps it until that one is.
            @Suppress("DEPRECATION")
            val token = runCatching { Tasks.await(FirebaseMessaging.getInstance().token) }.getOrNull()
            token?.let(::tokenChanged)
        }
    }

    /** Firebase gave a new token (the service's `onNewToken`). */
    fun tokenChanged(token: String) {
        scope.launch { runCatching { vault.setPushToken(PushPlatform.FCM, token, false) } }
    }

    /**
     * A push arrived. Blocks the push service's thread while the vault syncs, which keeps the
     * process up for it: unlocked, a full sync; locked, the ciphertext only (`syncOnPush`).
     */
    fun received(kind: PushKind) {
        if (kind == PushKind.Alert) postAlert()
        runCatching { runBlocking { withTimeoutOrNull(PUSH_SYNC_TIMEOUT_MS) { vault.syncOnPush() } } }
    }

    private fun createChannel() {
        // Created again at each start and alert, so its name follows the app's language.
        val channel = NotificationChannel(ALERT_CHANNEL, app.getString(R.string.phone_native_pushChannelName), NotificationManager.IMPORTANCE_DEFAULT)
        channel.description = app.getString(R.string.phone_native_pushChannelHelp)
        app.getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    /** The generic words only: the push says nothing more, and the vault may be locked. */
    private fun postAlert() {
        if (!canNotify(app)) return
        createChannel()
        val open = PendingIntent.getActivity(
            app,
            0,
            Intent(app, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val notification = NotificationCompat.Builder(app, ALERT_CHANNEL)
            .setSmallIcon(AppR.drawable.logo_mark)
            .setContentTitle(app.getString(R.string.phone_native_pushAlertTitle))
            .setContentText(app.getString(R.string.phone_native_pushAlertBody))
            .setStyle(NotificationCompat.BigTextStyle().bigText(app.getString(R.string.phone_native_pushAlertBody)))
            .setContentIntent(open)
            .setAutoCancel(true)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .build()
        try {
            NotificationManagerCompat.from(app).notify(ALERT_NOTIFICATION, notification)
        } catch (ignored: SecurityException) {
        }
    }

    companion object {
        fun canNotify(context: Context): Boolean {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
                ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
            ) {
                return false
            }
            return NotificationManagerCompat.from(context).areNotificationsEnabled()
        }
    }
}

/**
 * Android 13 and later ask before an app posts notifications. Octa Pass asks once, the first
 * time a synced vault is open and nothing else is on screen for it (not over the lock screen,
 * sign-up or a new Recovery Kit), and only in a build that gets pushes. Said no, it never asks
 * again: sync pushes still come, only the alert stays unshown. Call from `onCreate`.
 */
fun askForNotificationsOnce(activity: ComponentActivity, model: AppModel) {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
    val prefs = activity.getSharedPreferences("octapass.push", Context.MODE_PRIVATE)
    val ask = activity.registerForActivityResult(ActivityResultContracts.RequestPermission()) {}
    activity.lifecycleScope.launch {
        activity.repeatOnLifecycle(Lifecycle.State.RESUMED) {
            if (!model.push.available || prefs.getBoolean("askedNotifications", false)) return@repeatOnLifecycle
            if (PushLink.canNotify(activity)) return@repeatOnLifecycle
            combine(model.session, model.newKit) { session, kit ->
                session.status == SessionStatus.UNLOCKED && !session.isLocal && kit == null
            }.first { it }
            // The vault's screen first, then the question.
            delay(1_000)
            prefs.edit { putBoolean("askedNotifications", true) }
            ask.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }
}

/** Firebase Cloud Messaging's deliveries. Only data messages come, and only the kind is read. */
class PushMessages : FirebaseMessagingService() {
    private val push get() = (application as OctaPassApp).model.push

    @Deprecated("Kept with FirebaseMessaging.getToken, see PushLink.start")
    override fun onNewToken(token: String) = push.tokenChanged(token)

    override fun onMessageReceived(message: RemoteMessage) {
        PushKind.of(message.data)?.let(push::received)
    }
}
