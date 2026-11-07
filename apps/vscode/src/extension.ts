// Three things, as generic client of Octa Pass Connect: browse references, insert octapass://
// links, and run a command with secrets injected. Activation is on the commands and the view only.
// It talks to the local Connect endpoint and nothing else.

import * as vscode from 'vscode';
import { runLine } from './run';
import { Session } from './session';
import { referenceOf, ReferenceTree } from './tree';

const LAST_COMMAND = 'octapass.lastCommand';

async function insert(reference: string): Promise<void> {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    void vscode.window.showWarningMessage(vscode.l10n.t('Open a file to insert a reference.'));
    return;
  }
  await editor.edit((edit) => {
    for (const selection of editor.selections) {
      edit.replace(selection, reference);
    }
  });
}

async function insertReference(session: Session): Promise<void> {
  try {
    const rows = await session.rows();
    if (!rows) {
      await session.offerConnect(vscode.l10n.t('Connect to Octa Pass first.'));
      return;
    }
    const picked = await vscode.window.showQuickPick(
      rows.map((row) => ({
        label: `${row.vault} / ${row.item} / ${row.field}`,
        iconPath: new vscode.ThemeIcon(row.secret ? 'key' : 'symbol-field'),
        reference: row.reference,
      })),
      { placeHolder: vscode.l10n.t('Pick a field to insert') },
    );
    if (picked) {
      await insert(picked.reference);
    }
  } catch (error) {
    await session.report(error);
  }
}

async function runWithSecrets(state: vscode.Memento): Promise<void> {
  const command = await vscode.window.showInputBox({
    prompt: vscode.l10n.t('The command to run with secrets'),
    placeHolder: 'npm start',
    value: state.get<string>(LAST_COMMAND, ''),
  });
  if (!command?.trim()) {
    return;
  }
  await state.update(LAST_COMMAND, command.trim());
  const cliPath = vscode.workspace.getConfiguration('octapass').get<string>('cliPath', 'octapass');
  const active = vscode.window.activeTextEditor?.document.uri;
  const folder = (active && vscode.workspace.getWorkspaceFolder(active)) ?? vscode.workspace.workspaceFolders?.[0];
  const terminal = vscode.window.createTerminal({ name: 'Octa Pass', cwd: folder?.uri });
  terminal.show();
  terminal.sendText(runLine(cliPath, command, vscode.env.shell, process.platform));
}

export function activate(context: vscode.ExtensionContext): void {
  const session = new Session(context.secrets);
  const tree = new ReferenceTree(session);
  const view = vscode.window.createTreeView('octapass.references', { treeDataProvider: tree });
  tree.view = view;
  const command = (name: string, run: (...args: unknown[]) => unknown) =>
    vscode.commands.registerCommand(name, run);
  context.subscriptions.push(
    session,
    view,
    command('octapass.connect', () => session.connect()),
    command('octapass.disconnect', () => session.disconnect()),
    command('octapass.refresh', () => tree.refresh()),
    command('octapass.insertReference', () => insertReference(session)),
    command('octapass.insertField', async (node) => {
      const reference = referenceOf(node);
      if (reference) {
        await insert(reference);
      }
    }),
    command('octapass.runWithSecrets', () => runWithSecrets(context.workspaceState)),
  );
  void session.publish();
}

export function deactivate(): void {}
