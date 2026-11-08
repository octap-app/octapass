package app.octap.android.model

import android.app.Application
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import androidx.annotation.StringRes
import androidx.core.content.ContextCompat
import app.octap.android.BuildConfig
import app.octap.android.platform.AndroidPlatform
import app.octap.android.platform.Clipboard
import app.octap.android.platform.SafeDrives
import app.octap.android.platform.PushLink
import app.octap.android.platform.WatchCodesLink
import app.octap.android.ui.vault.VaultNavigator
import app.octap.android.vault.Container
import app.octap.android.vault.DeviceLock as PhoneLock
import app.octap.vault.DevicePlatform
import app.octap.vault.ErrorCode
import app.octap.vault.NewRecoveryKit
import app.octap.vault.OctaPassVault
import app.octap.vault.SessionSnapshot
import app.octap.vault.SessionStatus
import app.octap.vault.Settings
import app.octap.vault.SyncState
import app.octap.vault.SyncStatus
import app.octap.vault.VaultConfig
import app.octap.vault.VaultObserver
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.async
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

/** A short message at the bottom of the screen, with the haptic that goes with it. */
data class Toast(val text: String, val tone: Tone = Tone.Info) {
    enum class Tone { Info, Success, Danger }
}

/** A new Recovery Kit waiting for the user to save it, and what to say around it. */
data class PendingKit(val kit: NewRecoveryKit, val title: String, val body: String, val done: String? = null)

/** A vault on this device only (`isLocalServer`). Its session's email holds the vault's name. */
val SessionSnapshot.isLocal: Boolean get() = serverUrl?.startsWith("local:") == true

/** The steps around a local vault that take over the whole screen, see [AppModel.localFlow]. */
enum class LocalFlow { Create, Restore, TurnOnSync }

/**
 * The app's one [OctaPassVault] and what the screens watch: the session, the sync state, the
 * settings, and counters that tick when items or sharing change (the vault's [VaultObserver]
 * calls, which arrive on its own threads). Everything the screens do goes through [vault]; this
 * class only holds state and platform services.
 */
class AppModel(val app: Application) : VaultObserver {
    val platform = AndroidPlatform(app)
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)

    private val _session = MutableStateFlow(SessionSnapshot(SessionStatus.SIGNED_OUT, null, null, emptyList()))
    val session: StateFlow<SessionSnapshot> = _session.asStateFlow()

    /** The open vault is on this device only. Fixed for as long as the vault's screens are up. */
    val isLocal: Boolean get() = _session.value.isLocal

    /**
     * Stays up over the vault until it clears this itself: creating a vault and turning on sync
     * change the session, and still have the recovery code or the Recovery Kit to show.
     */
    val localFlow = MutableStateFlow<LocalFlow?>(null)

    private val _local = MutableStateFlow(0L)

    /** Ticks when a local vault's backups change, which the session doesn't report. */
    val localVersion: StateFlow<Long> = _local.asStateFlow()

    fun localChanged() {
        _local.value += 1
    }

    private val _items = MutableStateFlow(0L)

    /** Ticks whenever items changed here or elsewhere: lists and open items reload. */
    val itemsVersion: StateFlow<Long> = _items.asStateFlow()

    private val _sharing = MutableStateFlow(0L)
    val sharingVersion: StateFlow<Long> = _sharing.asStateFlow()

    private val _sync = MutableStateFlow(SyncState(SyncStatus.IDLE, null, null, false, 0u, 0uL))
    val sync: StateFlow<SyncState> = _sync.asStateFlow()

    private val _toasts = MutableSharedFlow<Toast>(extraBufferCapacity = 8)
    val toasts: SharedFlow<Toast> = _toasts.asSharedFlow()

    /**
     * A new Recovery Kit the user hasn't confirmed saving. Kept here, in memory only, because it's
     * the only copy: the screen that made it may be gone, and a lock must not lose it.
     */
    val newKit = MutableStateFlow<PendingKit?>(null)

    /** One-time code links the phone opened Octa Pass with, waiting for the unlocked vault. */
    val openedLinks = MutableStateFlow<List<String>>(emptyList())

    /** The open Safes, which lock with the vault. Before [vault]: it hears from the vault at once. */
    val safes = SafeDrives(app) { vault }

    val vault: OctaPassVault = OctaPassVault(
        VaultConfig(
            dataDir = Container.directory(app).apply { mkdirs() }.path,
            tempDir = File(app.cacheDir, "vault").apply { mkdirs() }.path,
            deviceName = deviceName(),
            platform = DevicePlatform.ANDROID,
            webVaultUrl = BuildConfig.WEB_VAULT_URL,
            defaultServerUrl = BuildConfig.DEFAULT_SERVER_URL,
        ),
        platform,
        this,
    )

    private val _settings = MutableStateFlow(vault.settings())
    val settings: StateFlow<Settings> = _settings.asStateFlow()

    val clipboard = Clipboard(app)

    /** A Wear OS watch's codes. What it gets is decided in the vault. */
    val watch = WatchCodesLink(app, vault)

    /** Push sync: the FCM token to the vault, and a sync when a push comes. Started by [OctaPassApp]. */
    val push = PushLink(app, vault)

    /** Accounts offered device unlock during this unlock, so recreating the window doesn't ask again. */
    val offeredDeviceUnlock: MutableSet<String> = java.util.Collections.synchronizedSet(mutableSetOf())

    private var navigator: Pair<String, VaultNavigator>? = null

    /**
     * The vault's screens for this account: kept while the vault is locked and when the window is
     * recreated (a language change), so the app comes back to the same place.
     */
    fun navigator(account: String): VaultNavigator {
        navigator?.let { (key, nav) -> if (key == account) return nav }
        return VaultNavigator().also { navigator = account to it }
    }

    /** Set while a system picker, the camera, a file viewer or a settings screen Octa Pass opened is in front. */
    @Volatile
    var inSystemUi = false

    init {
        _session.value = vault.snapshot()
        _sync.value = vault.syncState()
        safes.sessionChanged(_session.value.status)
        // The screen turning off (the phone sleeping or locking) ends what the last answer covered
        // (plan 18). Only while Octa Pass runs, which is as long as that answer is kept anyway.
        ContextCompat.registerReceiver(
            app,
            object : BroadcastReceiver() {
                override fun onReceive(context: Context, intent: Intent) = phoneLocked()
            },
            IntentFilter(Intent.ACTION_SCREEN_OFF),
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
    }

    /**
     * "Stay unlocked while you're logged in to this device" (plan 18) is on and this phone can do
     * it (a secure lock screen). Then the vault opens with no prompt ([unlockStayingUnlocked]),
     * the app-open gate doesn't apply, and revealing and copying ask once ([confirmReveal]).
     */
    val staysUnlocked: Boolean
        get() = _settings.value.stayUnlocked && PhoneLock.available(app)

    /** The one automatic unlock under way, shared by the app coming to the front and the lock screen. */
    private var stayUnlocking: Deferred<Boolean>? = null

    /**
     * Stay unlocked (plan 18): when the vault is locked and the setting is on, opens it with no
     * prompt. Called when the app starts or comes back to the front, and by the lock screen before
     * it asks anything. False means the lock screen asks as before: "Lock now" was used, the
     * 14-day master password check is due, there's no key or no screen lock. Never a confirmed
     * unlock: the first reveal or copy still asks. Main thread.
     */
    suspend fun unlockStayingUnlocked(): Boolean {
        if (!_settings.value.stayUnlocked || vault.snapshot().status != SessionStatus.LOCKED) return false
        val running = stayUnlocking?.takeIf { it.isActive }
            ?: scope.async { runCatching { vault.unlockStayUnlocked() }.getOrDefault(false) }.also { stayUnlocking = it }
        return running.await()
    }

    /**
     * The screen turned off: while staying unlocked, reveal and copy ask again (plan 18). With it
     * off, plan 03's once-per-unlock rule is unchanged, as on the desktop and in the extension.
     */
    fun phoneLocked() {
        if (staysUnlocked) cover.end()
    }

    /** The account was just deleted: the goodbye shows before the start. */
    val accountDeleted = MutableStateFlow(false)

    private val _identityRequest = MutableStateFlow<CompletableDeferred<Boolean>?>(null)

    /** A waiting "Confirm it's you", answered by `IdentityGateDialog`. */
    val identityRequest: StateFlow<CompletableDeferred<Boolean>?> = _identityRequest.asStateFlow()

    /**
     * The account whose unlock the user answered in the app (the device prompt, the master
     * password, signing in or up, a new or restored local vault), or whose first reveal while the
     * vault stays unlocked, until the vault next locks, another account opens or the screen turns
     * off. Reveal and copy don't ask again while it's set (plan 03 History, 2026-11-05; plan 18).
     */
    private val cover = RevealCover()

    private fun account(snapshot: SessionSnapshot) = "${snapshot.serverUrl.orEmpty()}\n${snapshot.email.orEmpty()}"

    /** The open vault's account, null while it's locked or signed out. Asks the vault, not the last event. */
    private fun unlockedAccount(): String? = vault.snapshot().takeIf { it.status == SessionStatus.UNLOCKED }?.let(::account)

    /**
     * Called by the screens that unlock the vault, right after the user's own answer opened it.
     * Nothing else unlocks this vault (the autofill service has its own), so an unlock that
     * doesn't come through here keeps asking. With the app-open gate off it isn't counted,
     * whatever opened the vault (maintainer decision, plan 03 History 2026-11-05), except while
     * the vault stays unlocked, where the gate doesn't apply (plan 18).
     */
    fun unlockWasConfirmed() = cover.unlockAnswered(unlockedAccount(), _settings.value.deviceAuthOnOpen, staysUnlocked)

    /**
     * Runs a screen's unlock (or sign-in, sign-up, new or restored local vault) and counts it with
     * [unlockWasConfirmed]. Not cancellable: the screen that asked leaves as the vault opens, and
     * its scope with it.
     */
    suspend fun <T> confirmedUnlock(unlock: suspend () -> T): T = withContext(NonCancellable) {
        unlock().also { unlockWasConfirmed() }
    }

    /**
     * This unlock was the user's answer and the vault hasn't locked since. Asks the vault, not the
     * last event, so a lock the screens haven't heard about yet still counts.
     */
    val unlockConfirmed: Boolean
        get() = cover.covers(unlockedAccount(), _settings.value.deviceAuthOnOpen, staysUnlocked)

    /**
     * An open vault covers revealing and copying, however it was opened (maintainer decision, plan
     * 03 History 2026-11-06): nothing asks while it's unlocked. Only export, saving to a file, the
     * Secret Key, the Recovery Kit and the account's own settings ask ([confirmIdentity]).
     */
    suspend fun unlockCoversReveal(): Boolean = unlockedAccount() != null

    /**
     * The gate for revealing and copying a field, showing a secret as a QR code, and showing an
     * SSH key or environment values: no prompt while the vault is open, however it was opened
     * (maintainer decision, plan 03 History 2026-11-06). Exports, the Secret Key and the account's
     * own settings ask every time ([confirmIdentity]). "Confirm it's you" here only if the vault
     * locked in the meantime.
     */
    suspend fun confirmReveal(): Boolean {
        if (unlockCoversReveal()) return true
        if (!confirmIdentity()) return false
        revealAnswered()
        return true
    }

    /**
     * The user just answered "Confirm it's you" for a reveal or copy. While the vault stays
     * unlocked (plan 18) that answer covers revealing and copying until the vault locks, the screen
     * turns off or another account opens, as an unlock they answered does. Otherwise nothing
     * changes: a vault opened without a check asks on every reveal.
     */
    fun revealAnswered() = cover.revealAnswered(unlockedAccount(), staysUnlocked)

    /**
     * "Confirm it's you", every time: before an export, the Secret Key or a change to the account
     * (plan 03, whatever the two gates say), and before a reveal the unlock doesn't cover. The
     * device lock where it's on, the master password otherwise. A device with no lock has the
     * master password as its only gate, so nobody gets through unasked. Cancelling the device
     * prompt is an answer; the master password is asked when the device lock can't be used.
     */
    suspend fun confirmIdentity(): Boolean {
        val methods = runCatching { vault.unlockMethods() }.getOrNull()
        if (methods != null && methods.deviceUnlockEnabled && !methods.passwordRequired) {
            try {
                vault.confirmUser(null)
                return true
            } catch (error: Exception) {
                if (error.code == ErrorCode.DEVICE_UNLOCK_CANCELLED) return false
            }
        }
        val answer = CompletableDeferred<Boolean>()
        _identityRequest.value?.complete(false)
        _identityRequest.value = answer
        return try {
            answer.await()
        } finally {
            _identityRequest.compareAndSet(answer, null)
        }
    }

    fun updateSettings(change: (Settings) -> Settings) {
        val before = _settings.value
        val next = change(before.copy())
        vault.updateSettings(next)
        val watchChanged = next.showCodesOnWatch != _settings.value.showCodesOnWatch
        _settings.value = next
        // Turning the app-open gate off ends what this unlock covered, until the next one (the
        // gate doesn't apply while the vault stays unlocked); so does turning stay unlocked off,
        // where an answer to a reveal covered it (plan 18).
        if ((!next.deviceAuthOnOpen && !staysUnlocked) || (before.stayUnlocked && !next.stayUnlocked)) cover.end()
        if (watchChanged) watchChanged()
    }

    /** The session or the setting changed: the watch gets codes or a clear straight away. */
    private fun watchChanged() {
        watch.update()
        watch.keepFresh(_session.value.status == SessionStatus.UNLOCKED && _settings.value.showCodesOnWatch)
    }

    fun toast(text: String, tone: Toast.Tone = Toast.Tone.Info) {
        _toasts.tryEmit(Toast(text, tone))
    }

    fun toast(@StringRes text: Int, tone: Toast.Tone = Toast.Tone.Info) = toast(app.getString(text), tone)

    fun toastError(error: Throwable) = toast(errorMessage(app, error), Toast.Tone.Danger)

    /** Runs a vault call from a screen, showing its error as a toast. */
    fun launch(work: suspend () -> Unit) = scope.launch {
        try {
            work()
        } catch (error: Exception) {
            if (error is kotlinx.coroutines.CancellationException) throw error
            toastError(error)
        }
    }

    // VaultObserver: called on a vault thread. StateFlow is safe to set from any thread.

    override fun sessionChanged(snapshot: SessionSnapshot) {
        val before = _session.value.status
        _session.value = snapshot
        // Signing out from the lock screen must not reveal a kit to whoever holds the phone.
        if (snapshot.status == SessionStatus.SIGNED_OUT) newKit.value = null
        safes.sessionChanged(snapshot.status)
        cover.sessionChanged(snapshot.takeIf { it.status == SessionStatus.UNLOCKED }?.let(::account))
        if (snapshot.status != SessionStatus.UNLOCKED) {
            clipboard.clearNow()
            offeredDeviceUnlock.clear()
        }
        if (snapshot.status != before) watchChanged()
    }

    override fun itemsChanged() {
        _items.value += 1
        if (_settings.value.showCodesOnWatch) watch.update()
        safes.refresh()
    }

    override fun syncChanged(state: SyncState) {
        val synced = state.status == SyncStatus.IDLE && state.lastSyncedAt != _sync.value.lastSyncedAt
        _sync.value = state
        // The synced Safes follow the vault.
        if (synced) safes.syncSoon()
    }

    override fun sharingChanged() {
        _sharing.value += 1
    }

    private fun deviceName(): String {
        val model = Build.MODEL.orEmpty().trim()
        return if (model.isEmpty()) "Octa Pass for Android" else "Octa Pass on $model"
    }
}
