package app.octap.android.platform

import android.Manifest
import android.annotation.SuppressLint
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.location.LocationManager
import android.net.wifi.WifiEnterpriseConfig
import android.net.wifi.WifiManager
import android.net.wifi.WifiNetworkSuggestion
import android.os.Build
import android.provider.Settings
import androidx.core.content.ContextCompat
import app.octap.vault.WifiDetails
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/** Why Connect couldn't start: the phone can't add this kind of network from an app. */
class WifiUnsupported(message: String) : Exception(message)

/** Android 11+ refused the network's details (an Enterprise network without a CA certificate or domain). */
class WifiInvalid(message: String) : Exception(message)

/**
 * Wi-Fi Connect (moved from the Tauri plugin's `WifiNetwork.kt`, same behaviour): the system's
 * "Save this network?" sheet (`ACTION_WIFI_ADD_NETWORKS`, Android 11+), which saves the network as
 * choosing it in Settings would; the phone joins it when it's in range.
 */
object WifiConnect {
    fun intent(wifi: WifiDetails): Intent {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) throw WifiUnsupported("Android 11 or later adds Wi-Fi networks from apps")
        val builder = WifiNetworkSuggestion.Builder().setSsid(wifi.ssid).setIsHiddenSsid(wifi.hidden)
        when {
            enterprise(wifi.security) -> builder.setWpa2EnterpriseConfig(enterpriseConfig(wifi))
            wifi.security == "open" -> Unit
            wifi.security == "wep" -> throw WifiUnsupported("Android doesn't let apps add WEP networks")
            wifi.security == "wpa3" -> builder.setWpa3Passphrase(wifi.password.orEmpty())
            else -> builder.setWpa2Passphrase(wifi.password.orEmpty())
        }
        val suggestion = try {
            builder.build()
        } catch (error: IllegalArgumentException) {
            throw WifiInvalid("invalid network details")
        }
        return Intent(Settings.ACTION_WIFI_ADD_NETWORKS).putParcelableArrayListExtra(Settings.EXTRA_WIFI_NETWORK_LIST, arrayListOf(suggestion))
    }

    fun enterprise(security: String) = security == "wpa2Enterprise" || security == "wpa3Enterprise"

    private fun enterpriseConfig(wifi: WifiDetails): WifiEnterpriseConfig {
        val method = wifi.eapMethod.orEmpty()
        val eap = eapMethod(method) ?: throw WifiUnsupported("Android can't join $method networks from apps")
        return WifiEnterpriseConfig().apply {
            eapMethod = eap
            phase2(method, wifi.phase2)?.let { phase2Method = it }
            wifi.username?.let { identity = it }
            wifi.password?.let { password = it }
            wifi.identity?.takeIf { it.isNotEmpty() }?.let { anonymousIdentity = it }
            wifi.serverDomain?.takeIf { it.isNotEmpty() }?.let { domainSuffixMatch = it }
            wifi.caCertificate?.let(::certificate)?.let { caCertificate = it }
        }
    }

    enum class Outcome { ADDED, CANCELLED, FAILED }

    /** What the system's sheet answered. */
    fun outcome(resultCode: Int, data: Intent?): Outcome {
        if (resultCode != Activity.RESULT_OK) return Outcome.CANCELLED
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) return Outcome.FAILED
        return outcome(data?.getIntegerArrayListExtra(Settings.EXTRA_WIFI_NETWORK_RESULT_LIST).orEmpty())
    }

    internal fun outcome(results: List<Int>): Outcome = when {
        results.isEmpty() -> Outcome.ADDED
        results.all { it == Settings.ADD_WIFI_RESULT_SUCCESS || it == Settings.ADD_WIFI_RESULT_ALREADY_EXISTS } -> Outcome.ADDED
        else -> Outcome.FAILED
    }

    /** `WifiEnterpriseConfig.Eap` for the vault's EAP method. LEAP, EAP-FAST and TLS (needs a client certificate) aren't there. */
    internal fun eapMethod(method: String): Int? = when (method) {
        "peap" -> 0
        "ttls" -> 2
        "pwd" -> 3
        else -> null
    }

    /** `WifiEnterpriseConfig.Phase2` for PEAP and TTLS, MSCHAPv2 when not set. */
    internal fun phase2(method: String, phase2: String?): Int? {
        if (method != "peap" && method != "ttls") return null
        return when (phase2) {
            "pap" -> 1
            "mschap" -> 2
            "gtc" -> 4
            else -> 3
        }
    }

    /** A pasted PEM certificate, or null when it isn't one. */
    internal fun certificate(pem: String): X509Certificate? = try {
        CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(pem.trim().toByteArray())) as X509Certificate
    } catch (error: Exception) {
        null
    }
}

/** The phone's Wi-Fi as Android reports it, for the "Connected" and "In range" marks (from the Tauri plugin). */
object WifiReading {
    data class Sighting(val ssid: String, val signal: Int)

    enum class Permission { GRANTED, PROMPT, DENIED }

    /** `WifiInfo.getSSID()`: quoted when it's UTF-8, bare hex otherwise, `<unknown ssid>` without location access. */
    fun ssid(raw: String?): String? {
        if (raw.isNullOrEmpty() || raw == "<unknown ssid>" || raw == "0x") return null
        if (raw.length >= 2 && raw.startsWith('"') && raw.endsWith('"')) return raw.substring(1, raw.length - 1).ifEmpty { null }
        return null
    }

    /** Signal from dBm (-100 is nothing, -50 or stronger is full) to 0–100, as on the computers. */
    fun signal(dbm: Int): Int = ((dbm + 100) * 2).coerceIn(0, 100)

    /** Scan results (name, dBm) as one sighting per name, the strongest, strongest first. Hidden networks are left out. */
    fun sightings(results: List<Pair<String?, Int>>): List<Sighting> =
        results
            .mapNotNull { (ssid, dbm) -> ssid?.takeIf { it.isNotEmpty() }?.let { Sighting(it, signal(dbm)) } }
            .groupBy { it.ssid }
            .map { (_, same) -> same.maxBy { it.signal } }
            .sortedWith(compareByDescending<Sighting> { it.signal }.thenBy { it.ssid })

    /** Bars, 1 to 4, the way the system shows them (`signalBars`). */
    fun bars(signal: Int): Int = when {
        signal >= 75 -> 4
        signal >= 50 -> 3
        signal >= 25 -> 2
        else -> 1
    }

    fun permission(context: Context, asked: Boolean): Permission {
        val location = context.getSystemService(LocationManager::class.java)
        // With location off for the whole phone, Android hides network names from every app.
        if (!location.isLocationEnabled) return Permission.DENIED
        val granted = ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED
        return when {
            granted -> Permission.GRANTED
            asked -> Permission.DENIED
            else -> Permission.PROMPT
        }
    }

    @SuppressLint("MissingPermission")
    @Suppress("DEPRECATION")
    fun current(context: Context): String? = ssid(manager(context).connectionInfo?.ssid)

    /**
     * Networks in range from the last scan. A rescan asks for a new one, which Android allows only
     * four times in two minutes; when it says no, the last results still answer.
     */
    @SuppressLint("MissingPermission")
    @Suppress("DEPRECATION")
    fun nearby(context: Context, rescan: Boolean): List<Sighting> {
        val wifi = manager(context)
        if (rescan) wifi.startScan()
        return sightings(wifi.scanResults.orEmpty().map { it.SSID to it.level })
    }

    private fun manager(context: Context) = context.applicationContext.getSystemService(WifiManager::class.java)
}
