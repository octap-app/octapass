package app.octap.jetbrains

import com.intellij.notification.NotificationType
import com.intellij.openapi.command.WriteCommandAction
import com.intellij.openapi.editor.Editor
import com.intellij.openapi.fileEditor.FileEditorManager
import com.intellij.openapi.project.Project

/** Into the editor given, or the selected one. Replaces a selection, as typing would. */
fun insertReference(project: Project, reference: String, target: Editor? = null) {
    val editor = target ?: FileEditorManager.getInstance(project).selectedTextEditor
    if (editor == null) {
        ConnectSession.get().notify(project, message("insert.noEditor"), NotificationType.WARNING)
        return
    }
    WriteCommandAction.runWriteCommandAction(project, message("action.OctaPass.InsertReference.text"), null, {
        editor.caretModel.runForEachCaret { caret ->
            val start = caret.selectionStart
            editor.document.replaceString(start, caret.selectionEnd, reference)
            caret.removeSelection()
            caret.moveToOffset(start + reference.length)
        }
    })
}
