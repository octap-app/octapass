// Vault > item > field. Names only: nothing here asks for a value.

package app.octap.jetbrains

import app.octap.connect.ConnectException
import app.octap.connect.Failure
import app.octap.connect.FieldRow
import com.intellij.icons.AllIcons
import com.intellij.openapi.actionSystem.ActionGroup
import com.intellij.openapi.actionSystem.ActionManager
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.application.ModalityState
import com.intellij.openapi.project.DumbAware
import com.intellij.openapi.project.Project
import com.intellij.openapi.ui.SimpleToolWindowPanel
import com.intellij.openapi.wm.ToolWindow
import com.intellij.openapi.wm.ToolWindowFactory
import com.intellij.ui.ColoredListCellRenderer
import com.intellij.ui.ColoredTreeCellRenderer
import com.intellij.ui.DoubleClickListener
import com.intellij.ui.ScrollPaneFactory
import com.intellij.ui.SimpleTextAttributes
import com.intellij.ui.content.ContentFactory
import com.intellij.ui.treeStructure.Tree
import java.awt.event.KeyAdapter
import java.awt.event.KeyEvent
import java.awt.event.MouseEvent
import java.util.concurrent.atomic.AtomicInteger
import javax.swing.JList
import javax.swing.JTree
import javax.swing.tree.DefaultMutableTreeNode
import javax.swing.tree.DefaultTreeModel
import javax.swing.tree.TreeSelectionModel

class OctaPassToolWindowFactory : ToolWindowFactory, DumbAware {
    override fun createToolWindowContent(project: Project, toolWindow: ToolWindow) {
        val panel = ReferencesPanel(project, toolWindow)
        val content = ContentFactory.getInstance().createContent(panel, "", false)
        toolWindow.contentManager.addContent(content)
    }
}

private class VaultNode(val name: String)

private class ItemNode(val name: String)

private class ReferencesPanel(
    private val project: Project,
    toolWindow: ToolWindow,
) : SimpleToolWindowPanel(true, true) {
    private val model = DefaultTreeModel(DefaultMutableTreeNode())
    private val tree = Tree(model)
    private val loads = AtomicInteger()

    init {
        tree.isRootVisible = false
        tree.showsRootHandles = true
        tree.selectionModel.selectionMode = TreeSelectionModel.SINGLE_TREE_SELECTION
        tree.cellRenderer = NodeRenderer()
        object : DoubleClickListener() {
            override fun onDoubleClick(event: MouseEvent): Boolean = insertSelected()
        }.installOn(tree)
        tree.addKeyListener(object : KeyAdapter() {
            override fun keyPressed(event: KeyEvent) {
                if (event.keyCode == KeyEvent.VK_ENTER && insertSelected()) {
                    event.consume()
                }
            }
        })
        setContent(ScrollPaneFactory.createScrollPane(tree, true))
        val actions = ActionManager.getInstance()
        val toolbar = actions.createActionToolbar(
            "OctaPass.ToolWindow",
            actions.getAction("OctaPass.ToolWindow") as ActionGroup,
            true,
        )
        toolbar.targetComponent = this
        setToolbar(toolbar.component)
        ApplicationManager.getApplication().messageBus.connect(toolWindow.disposable)
            .subscribe(SessionListener.TOPIC, SessionListener { load() })
        load()
    }

    private fun insertSelected(): Boolean {
        val node = tree.lastSelectedPathComponent as? DefaultMutableTreeNode
        val row = node?.userObject as? FieldRow ?: return false
        insertReference(project, row.reference)
        return true
    }

    private fun load() {
        val load = loads.incrementAndGet()
        ApplicationManager.getApplication().executeOnPooledThread {
            val session = ConnectSession.get()
            var empty = message("tree.empty")
            val rows = try {
                session.rows().also { if (it == null) empty = message("tree.connect") }
            } catch (error: ConnectException) {
                empty = describe(error)
                if (error.failure == Failure.UNAUTHORIZED) {
                    session.report(project, error)
                }
                null
            }
            ApplicationManager.getApplication().invokeLater({
                if (load == loads.get()) {
                    show(rows.orEmpty(), empty)
                }
            }, ModalityState.any())
        }
    }

    private fun show(rows: List<FieldRow>, empty: String) {
        val root = DefaultMutableTreeNode()
        for ((vault, inVault) in rows.groupBy { it.vault }) {
            val vaultNode = DefaultMutableTreeNode(VaultNode(vault))
            // By id, since two items can have the same name.
            for (inItem in inVault.groupBy { it.itemId }.values) {
                val itemNode = DefaultMutableTreeNode(ItemNode(inItem.first().item))
                inItem.forEach { itemNode.add(DefaultMutableTreeNode(it)) }
                vaultNode.add(itemNode)
            }
            root.add(vaultNode)
        }
        tree.emptyText.text = empty
        model.setRoot(root)
    }
}

private class NodeRenderer : ColoredTreeCellRenderer() {
    override fun customizeCellRenderer(
        tree: JTree,
        value: Any?,
        selected: Boolean,
        expanded: Boolean,
        leaf: Boolean,
        row: Int,
        hasFocus: Boolean,
    ) {
        when (val node = (value as? DefaultMutableTreeNode)?.userObject) {
            is VaultNode -> {
                icon = AllIcons.Nodes.Folder
                append(node.name)
            }
            is ItemNode -> {
                icon = AllIcons.FileTypes.Any_type
                append(node.name)
            }
            is FieldRow -> {
                icon = if (node.secret) AllIcons.Nodes.SecurityRole else AllIcons.Nodes.Field
                append(node.field)
                toolTipText = node.reference
            }
        }
    }
}

class FieldRowRenderer : ColoredListCellRenderer<FieldRow>() {
    override fun customizeCellRenderer(
        list: JList<out FieldRow>,
        value: FieldRow,
        index: Int,
        selected: Boolean,
        hasFocus: Boolean,
    ) {
        icon = if (value.secret) AllIcons.Nodes.SecurityRole else AllIcons.Nodes.Field
        append("${value.vault} / ${value.item} / ")
        append(value.field, SimpleTextAttributes.REGULAR_BOLD_ATTRIBUTES)
    }
}
