package app.octap.jetbrains

import app.octap.connect.ConnectException
import app.octap.connect.FieldRow
import app.octap.connect.Place
import app.octap.connect.runLine
import com.intellij.ide.util.PropertiesComponent
import com.intellij.openapi.actionSystem.ActionUpdateThread
import com.intellij.openapi.actionSystem.AnAction
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.actionSystem.CommonDataKeys
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.editor.Editor
import com.intellij.openapi.progress.ProgressIndicator
import com.intellij.openapi.progress.ProgressManager
import com.intellij.openapi.progress.Task
import com.intellij.openapi.project.DumbAwareAction
import com.intellij.openapi.project.Project
import com.intellij.openapi.ui.Messages
import com.intellij.openapi.ui.popup.JBPopupFactory
import com.intellij.openapi.wm.ToolWindowManager
import org.jetbrains.plugins.terminal.TerminalProjectOptionsProvider
import org.jetbrains.plugins.terminal.TerminalToolWindowManager

const val CLI_PATH_KEY = "octapass.cliPath"
private const val LAST_COMMAND_KEY = "octapass.lastCommand"

abstract class BackgroundUpdateAction : DumbAwareAction() {
    override fun getActionUpdateThread() = ActionUpdateThread.BGT
}

class ConnectAction : BackgroundUpdateAction() {
    override fun actionPerformed(event: AnActionEvent) = ConnectSession.get().connect(event.project)
}

class DisconnectAction : BackgroundUpdateAction() {
    override fun actionPerformed(event: AnActionEvent) = ConnectSession.get().disconnect(event.project)
}

class RefreshAction : BackgroundUpdateAction() {
    override fun actionPerformed(event: AnActionEvent) {
        ApplicationManager.getApplication().messageBus.syncPublisher(SessionListener.TOPIC).changed()
    }
}

class InsertReferenceAction : BackgroundUpdateAction() {
    override fun update(event: AnActionEvent) {
        event.presentation.isEnabled = event.project != null && event.getData(CommonDataKeys.EDITOR) != null
    }

    override fun actionPerformed(event: AnActionEvent) {
        val project = event.project ?: return
        val editor = event.getData(CommonDataKeys.EDITOR) ?: return
        val session = ConnectSession.get()
        ProgressManager.getInstance().run(object : Task.Backgroundable(project, message("insert.loading"), true) {
            override fun run(indicator: ProgressIndicator) {
                val rows = try {
                    session.rows()
                } catch (error: ConnectException) {
                    session.report(project, error)
                    return
                }
                if (rows == null) {
                    session.offerConnect(project, message("insert.connectFirst"))
                    return
                }
                ApplicationManager.getApplication().invokeLater { choose(project, editor, rows) }
            }
        })
    }

    private fun choose(project: Project, editor: Editor, rows: List<FieldRow>) {
        if (editor.isDisposed) {
            return
        }
        JBPopupFactory.getInstance()
            .createPopupChooserBuilder(rows)
            .setTitle(message("insert.pick"))
            .setRenderer(FieldRowRenderer())
            .setNamerForFiltering { "${it.vault} ${it.item} ${it.field}" }
            .setItemChosenCallback { insertReference(project, it.reference, editor) }
            .createPopup()
            .showInBestPositionFor(editor)
    }
}

class RunWithSecretsAction : BackgroundUpdateAction() {
    override fun update(event: AnActionEvent) {
        event.presentation.isEnabled = event.project != null
    }

    override fun actionPerformed(event: AnActionEvent) {
        val project = event.project ?: return
        val state = PropertiesComponent.getInstance(project)
        val command = Messages.showInputDialog(
            project,
            message("run.prompt"),
            message("action.OctaPass.RunWithSecrets.text"),
            null,
            state.getValue(LAST_COMMAND_KEY, ""),
            null,
        )?.trim()
        if (command.isNullOrEmpty()) {
            return
        }
        state.setValue(LAST_COMMAND_KEY, command)
        // Application level on purpose: nothing in a project can choose the program that runs.
        val cliPath = PropertiesComponent.getInstance().getValue(CLI_PATH_KEY, "octapass")
        val shell = TerminalProjectOptionsProvider.getInstance(project).shellPath
        ToolWindowManager.getInstance(project).getToolWindow("Terminal")?.activate(null)
        TerminalToolWindowManager.getInstance(project)
            .createShellWidget(project.basePath, "Octa Pass", true, false)
            .sendCommandToExecute(runLine(cliPath, command, shell, Place.current().os))
    }
}
