package app.octap.jetbrains

import com.intellij.ide.util.PropertiesComponent
import com.intellij.openapi.options.Configurable
import com.intellij.ui.components.JBLabel
import com.intellij.ui.components.JBTextField
import com.intellij.util.ui.FormBuilder
import javax.swing.JComponent
import javax.swing.JPanel

/** The CLI path. Application level, so no project can change the program that runs. */
class OctaPassConfigurable : Configurable {
    private val field = JBTextField()

    override fun getDisplayName() = "Octa Pass"

    override fun createComponent(): JComponent = FormBuilder.createFormBuilder()
        .addLabeledComponent(JBLabel(message("settings.cliPath")), field)
        .addComponent(JBLabel(message("settings.cliPath.help")))
        .addComponentFillVertically(JPanel(), 0)
        .panel

    private fun stored() = PropertiesComponent.getInstance().getValue(CLI_PATH_KEY, "octapass")

    override fun isModified() = field.text.trim() != stored()

    override fun apply() {
        PropertiesComponent.getInstance().setValue(CLI_PATH_KEY, field.text.trim().ifEmpty { "octapass" })
    }

    override fun reset() {
        field.text = stored()
    }
}
