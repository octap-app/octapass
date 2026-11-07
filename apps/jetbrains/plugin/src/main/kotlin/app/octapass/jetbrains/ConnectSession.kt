// The token, kept only in PasswordSafe, and what each answer from Connect means for the person.
// PasswordSafe and Connect both block, so everything here runs off the event thread.

package app.octap.jetbrains

import app.octap.connect.ConnectClient
import app.octap.connect.ConnectException
import app.octap.connect.Failure
import app.octap.connect.FieldRow
import app.octap.connect.Place
import app.octap.connect.fieldRows
import app.octap.connect.findEndpoint
import com.intellij.credentialStore.CredentialAttributes
import com.intellij.credentialStore.Credentials
import com.intellij.credentialStore.generateServiceName
import com.intellij.ide.passwordSafe.PasswordSafe
import com.intellij.notification.NotificationAction
import com.intellij.notification.NotificationGroupManager
import com.intellij.notification.NotificationType
import com.intellij.openapi.application.ApplicationInfo
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.components.Service
import com.intellij.openapi.components.service
import com.intellij.openapi.progress.ProgressIndicator
import com.intellij.openapi.progress.ProgressManager
import com.intellij.openapi.progress.Task
import com.intellij.openapi.project.Project
import com.intellij.util.EnvironmentUtil
import com.intellij.util.messages.Topic

fun interface SessionListener {
    fun changed()

    companion object {
        val TOPIC = Topic(SessionListener::class.java)
    }
}

/** What to tell the person. */
fun describe(error: ConnectException): String = when (error.failure) {
    Failure.NOT_RUNNING -> message("error.notRunning")
    Failure.BAD_ENDPOINT -> message("error.badEndpoint")
    Failure.LOCKED -> message("error.locked")
    Failure.UNAUTHORIZED -> message("error.unauthorized")
    Failure.DENIED -> message("error.denied")
    Failure.BUSY -> message("error.busy")
    Failure.TIMED_OUT -> message("error.timedOut")
    Failure.BAD_RESPONSE -> message("error.badResponse")
    else -> if (error.status != null) message("error.failed", error.message.orEmpty()) else message("error.refused")
}

@Service(Service.Level.APP)
class ConnectSession {
    private val attributes = CredentialAttributes(generateServiceName("Octa Pass", "Connect token"))

    private fun token(): String? = PasswordSafe.instance.getPassword(attributes)

    private fun setToken(token: String?) {
        PasswordSafe.instance.set(attributes, token?.let { Credentials("connect", it) })
        ApplicationManager.getApplication().messageBus.syncPublisher(SessionListener.TOPIC).changed()
    }

    // EnvironmentUtil: an IDE started from the Dock doesn't have the shell's variables otherwise.
    private fun client(token: String? = null) =
        ConnectClient(findEndpoint(Place.current(EnvironmentUtil.getEnvironmentMap())), token)

    fun connected(): Boolean = token() != null

    /** The rows of the vaults, or null if there's no token. A token that no longer works is dropped. */
    fun rows(): List<FieldRow>? {
        val token = token() ?: return null
        try {
            return fieldRows(client(token).items())
        } catch (error: ConnectException) {
            if (error.failure == Failure.UNAUTHORIZED) {
                setToken(null)
            }
            throw error
        }
    }

    private fun pair(indicator: ProgressIndicator) {
        val name = ApplicationInfo.getInstance().versionName.take(64)
        setToken(client().pair(name) { indicator.isCanceled }.token)
    }

    /** True when Connect let go of the token, or had already. */
    private fun forget(): Boolean {
        val token = token() ?: return true
        val revoked = try {
            client(token).forget()
            true
        } catch (error: ConnectException) {
            error.failure == Failure.UNAUTHORIZED
        }
        setToken(null)
        return revoked
    }

    fun connect(project: Project?) {
        val title = message("connect.waiting")
        ProgressManager.getInstance().run(object : Task.Backgroundable(project, title, true) {
            override fun run(indicator: ProgressIndicator) {
                try {
                    if (rows() != null) {
                        notify(project, message("connect.already"), NotificationType.INFORMATION)
                        return
                    }
                } catch (error: ConnectException) {
                    if (error.failure != Failure.UNAUTHORIZED) {
                        report(project, error)
                        return
                    }
                }
                try {
                    pair(indicator)
                    notify(project, message("connect.done"), NotificationType.INFORMATION)
                } catch (error: ConnectException) {
                    report(project, error)
                }
            }
        })
    }

    fun disconnect(project: Project?) {
        ApplicationManager.getApplication().executeOnPooledThread {
            val text = if (forget()) message("disconnect.done") else message("disconnect.unreachable")
            notify(project, text, NotificationType.INFORMATION)
        }
    }

    /** Shows an error, and offers to connect when that's the way out. */
    fun report(project: Project?, error: ConnectException) {
        when (error.failure) {
            Failure.CANCELLED -> Unit
            Failure.UNAUTHORIZED -> offerConnect(project, describe(error))
            else -> notify(project, describe(error), NotificationType.ERROR)
        }
    }

    fun offerConnect(project: Project?, text: String) {
        val action = NotificationAction.createSimpleExpiring(message("action.OctaPass.Connect.text")) { connect(project) }
        group().createNotification(text, NotificationType.WARNING).addAction(action).notify(project)
    }

    fun notify(project: Project?, text: String, type: NotificationType) {
        group().createNotification(text, type).notify(project)
    }

    private fun group() = NotificationGroupManager.getInstance().getNotificationGroup("Octa Pass")

    companion object {
        fun get(): ConnectSession = service()
    }
}
