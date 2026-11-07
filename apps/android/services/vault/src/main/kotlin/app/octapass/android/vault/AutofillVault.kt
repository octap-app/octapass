package app.octap.android.vault

import android.content.Context
import app.octap.core.ClientData
import app.octap.core.CredentialExport
import app.octap.core.LocalStore
import app.octap.core.LoginDraft
import app.octap.core.OctaPassException
import app.octap.core.PasskeyAssertion
import app.octap.core.PasskeyAssertionRequest
import app.octap.core.PasskeyCreationRequest
import app.octap.core.PasskeyMatch
import app.octap.core.PasskeyRegistration
import app.octap.core.Session
import app.octap.core.websiteForPage
import java.io.File
import java.net.IDN
import java.net.URI
import java.util.Base64

/** A login that can fill the requesting site or app. */
data class Login(
    val itemId: String,
    val title: String,
    val username: String?,
    /** The saved URL that matched, or the login's first URL. */
    val url: String?,
    /** The page uses `http` while the login was saved for `https` (or the other way): warn. */
    val schemeMismatch: Boolean,
    val hasTotp: Boolean,
)

/**
 * A login saved for another part of the page's domain (`shop.example.com` on `login.example.com`).
 * Never a suggestion: listed behind one entry ("Logins for other parts of example.com") and filled
 * only when the user picks it.
 */
data class OtherPartLogin(
    val login: Login,
    /** The saved URL's host, as shown: Unicode, without a leading `www.`. */
    val host: String,
    /** The registrable domain the page and the login share, as shown ("example.com"). */
    val site: String,
    /** The login's vault can be changed, so the page's website may be added to it ([AutofillVault.addWebsite]). */
    val canAddWebsite: Boolean,
)

/** Nobody is signed in to the app, or its Secret Key is gone. */
class SignedOutException : Exception("signed out of Octa Pass")

/**
 * The current account's shared store, as the Autofill and Credential Manager services see it.
 * Nothing here touches the network: what they save (new logins and passkeys) waits in the store
 * until the app uploads it, on its next sync. Close it as soon as a fill is done, which zeroes the
 * keys.
 */
class AutofillVault private constructor(
    val account: Container.Account,
    private val store: LocalStore,
    private val secrets: Secrets,
    private val chip: ChipSecrets,
    private val stayUnlocked: StayUnlockedKeys? = null,
) : AutoCloseable {
    private var session: Session? = null

    /** Device unlock is on and the master password isn't due (every 14 days, plan 03). */
    val deviceUnlockAvailable: Boolean
        get() = store.deviceUnlockStatus().let { it.enabled && !it.passwordRequired }

    val isUnlocked: Boolean get() = session?.isLocked() == false

    /**
     * Saves a login without unlocking (plan 03, Saving while locked): it's sealed into the store's
     * save inbox with the account's own public keys, and added to the vault at the next unlock (the
     * app's, or an autofill screen's). False when the inbox can't take it: no unlock here has pinned
     * its key yet, or it's full (50).
     */
    fun saveLocked(url: String, username: String?, password: String, title: String? = null): Boolean {
        if (!store.inboxAccepts()) return false
        store.addToInbox(url, username?.ifEmpty { null }, password, title)
        return true
    }

    /**
     * Stay unlocked (plan 18): opens with the key the app kept for this account, with no prompt.
     * The key being there is the setting being on. False, for today's unlock instead, when there's
     * no key (the setting is off, the phone has no screen lock or is locked right now), the 14-day
     * master password check is due, or the key no longer opens the account (then it's deleted, as
     * the app does).
     */
    fun unlockStayingUnlocked(): Boolean {
        val keys = stayUnlocked ?: return false
        val key = keys.get(account.stayUnlockedName) ?: return false
        return try {
            replace(store.unlockStayUnlocked(key))
            true
        } catch (error: OctaPassException.PasswordRequired) {
            false
        } catch (error: OctaPassException.DeviceUnlockFailed) {
            keys.delete(account.stayUnlockedName)
            false
        } finally {
            key.fill(0)
        }
    }

    /** With the secret [DevicePrompt] released; the secret is zeroed. */
    fun unlockWithDevice(secret: ByteArray) {
        try {
            replace(store.unlockWithDevice(secret))
        } finally {
            secret.fill(0)
        }
    }

    /** Runs Argon2id: call it off the main thread. */
    fun unlockWithPassword(password: String) {
        if (store.isLocal()) {
            val context = account.chipContext?.let { Base64.getUrlDecoder().decode(it) }
            val secret = context?.let { chip.secret(account.chipKeyName, it) }
            try {
                replace(store.unlockLocal(password, secret))
            } finally {
                secret?.fill(0)
            }
            return
        }
        val secretKey = secrets.get(account.secretKeyName) ?: throw SignedOutException()
        replace(store.unlockWithPassword(password, secretKey))
    }

    /** Logins for the requesting site or app, best match first, each login once. */
    fun logins(urls: List<String>): List<Login> {
        val session = unlocked()
        return urls.flatMap { session.matchLogins(store, it) }
            .distinctBy { it.item.itemId }
            .map { Login(it.item.itemId, it.item.title, it.item.username, it.url, it.schemeMismatch, it.item.hasTotp) }
    }

    /**
     * The logins saved for other parts of [url]'s domain, which [logins] leaves out, sorted by
     * host. Empty for an app's `androidapp://` address.
     */
    fun otherLogins(url: String): List<OtherPartLogin> =
        unlocked().otherLogins(store, url).map {
            OtherPartLogin(
                Login(it.item.itemId, it.item.title, it.item.username, it.url, it.schemeMismatch, it.item.hasTotp),
                it.host,
                it.site,
                it.canAddWebsite,
            )
        }

    /**
     * Adds the page's website (`https://login.example.com`) to a login the user filled from
     * another part of its domain, so it's suggested here next time. A login that already has it
     * is left as it is. Saved to the store; the app uploads it on its next sync.
     */
    fun addWebsite(itemId: String, url: String) {
        val website = websiteForPage(url) ?: return
        unlocked().saveLogin(
            store,
            LoginDraft(itemId = itemId, title = null, url = website, username = null, password = null, totp = null),
        )
    }

    /** Every login whose title, user name or URL contains [query], for a site that doesn't match. */
    fun search(query: String): List<Login> {
        val needle = query.trim().lowercase()
        return unlocked().listItems(store)
            .filter { it.itemType == "login" || it.itemType == "password" }
            .filter { item -> needle.isEmpty() || (listOf(item.title, item.username.orEmpty()) + item.urls).any { it.lowercase().contains(needle) } }
            .map { Login(it.itemId, it.title, it.username, it.urls.firstOrNull(), false, it.hasTotp) }
    }

    /** The user name and password of a login. */
    fun credentials(itemId: String): Pair<String, String> {
        val login = unlocked().getItem(store, itemId).login
        return (login?.username.orEmpty()) to (login?.password.orEmpty())
    }

    fun oneTimeCode(itemId: String): String = unlocked().totpCode(store, itemId).code

    /**
     * Saves a password the user just used: it updates the login with this user name for the site
     * (the old password moves to its history), or creates one called [title] (by default, after
     * the website). Returns the item id.
     */
    fun saveLogin(url: String, username: String?, password: String, title: String? = null): String {
        val session = unlocked()
        val existing = session.matchLogins(store, url).firstOrNull {
            !username.isNullOrEmpty() && it.item.username.equals(username, ignoreCase = true)
        }
        return session.saveLogin(
            store,
            LoginDraft(
                itemId = existing?.item?.itemId,
                title = if (existing == null) title else null,
                url = url,
                username = if (existing == null) username?.ifEmpty { null } else null,
                password = password,
                totp = null,
            ),
        )
    }

    fun passkeys(request: PasskeyAssertionRequest, client: ClientData): List<PasskeyMatch> =
        unlocked().findPasskeys(store, request, client)

    fun assertion(request: PasskeyAssertionRequest, client: ClientData, credentialId: ByteArray): PasskeyAssertion =
        unlocked().getPasskeyAssertion(store, request, client, credentialId)

    /** Creates a passkey and saves it to the store before returning it, so it's never lost. */
    fun register(request: PasskeyCreationRequest, client: ClientData): PasskeyRegistration =
        unlocked().createPasskey(store, request, client)

    /**
     * Every item outside the trash as CXF, with only the [credentialTypes] another password
     * manager asked for. Plaintext: only after the master password, straight to that app.
     */
    fun exportForApp(credentialTypes: Set<String>): CredentialExport =
        unlocked().exportForApp(store, credentialTypes.toList(), exporterId(account.serverUrl))

    fun lock() {
        session?.lock()
        session?.close()
        session = null
    }

    override fun close() {
        lock()
        store.close()
    }

    private fun replace(new: Session) {
        lock()
        session = new
        // Every unlock pins the inbox key and merges what was saved while locked. A failure keeps
        // the entries for the next unlock and never stands in the way of this one.
        runCatching { store.mergeInbox(new) }
    }

    private fun unlocked(): Session = session?.takeUnless { it.isLocked() } ?: throw IllegalStateException("locked")

    companion object {
        /** CXF's `exporterRpId`: the server's host, as the app's own CXF export writes it. */
        fun exporterId(serverUrl: String): String =
            serverUrl.substringAfter("://").substringBefore('/').substringBefore(':')

        /** A page's host as the user knows it: Unicode, without a leading `www.`; null for an app. */
        fun displayHost(url: String): String? {
            if (url.startsWith("androidapp://")) return null
            val host = runCatching { URI(url).host }.getOrNull()?.lowercase()?.trimEnd('.') ?: return null
            val unicode = runCatching { IDN.toUnicode(host) }.getOrDefault(host)
            return unicode.removePrefix("www.").ifEmpty { null }
        }

        /** The current account's store, or null when nobody is signed in. */
        fun open(context: Context, secrets: Secrets = Secrets(context)): AutofillVault? {
            Core.load()
            val directory = Container.directory(context)
            val account = Container.currentAccount(directory) ?: return null
            val file = File(directory, account.storeFile)
            if (!file.isFile) return null
            return AutofillVault(account, LocalStore.open(file.path), secrets, ChipSecrets(context), StayUnlockedKeys(context))
        }
    }
}
