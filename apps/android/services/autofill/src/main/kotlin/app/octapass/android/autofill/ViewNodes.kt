package app.octap.android.autofill

import android.app.assist.AssistStructure
import android.view.View

/** [FormNode] over the framework's view tree. */
private class ViewNodeForm(private val node: AssistStructure.ViewNode) : FormNode {
    override val id get() = node.autofillId
    override val isTextField get() = node.autofillType == View.AUTOFILL_TYPE_TEXT && node.visibility == View.VISIBLE
    override val autofillHints get() = node.autofillHints?.toList().orEmpty()
    override val htmlAttributes: Map<String, String>
        get() = node.htmlInfo?.attributes?.mapNotNull { pair -> pair.first?.let { it.lowercase() to pair.second.orEmpty() } }?.toMap().orEmpty()
    override val inputType get() = node.inputType
    override val idEntry: String? get() = node.idEntry
    override val hint: String? get() = node.hint
    override val isFocused get() = node.isFocused
    override val text get() = node.autofillValue?.takeIf { it.isText }?.textValue?.toString()
    override val webDomain: String? get() = node.webDomain
    override val webScheme: String? get() = node.webScheme
    override val children get() = (0 until node.childCount).map { ViewNodeForm(node.getChildAt(it)) }
}

fun AssistStructure.form(): Form =
    FormParser.parse(activityComponent.packageName, (0 until windowNodeCount).map { ViewNodeForm(getWindowNodeAt(it).rootViewNode) })
