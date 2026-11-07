// Vault > item > field. Names only: nothing here asks for a value.

import * as vscode from 'vscode';
import { ConnectError } from './connect';
import type { FieldRow } from './references';
import { describe, type Session } from './session';

type Node =
  | { kind: 'vault'; name: string; rows: FieldRow[] }
  | { kind: 'item'; name: string; rows: FieldRow[] }
  | { kind: 'field'; row: FieldRow };

function grouped(rows: FieldRow[], key: (row: FieldRow) => string): Map<string, FieldRow[]> {
  const groups = new Map<string, FieldRow[]>();
  for (const row of rows) {
    const list = groups.get(key(row));
    if (list) {
      list.push(row);
    } else {
      groups.set(key(row), [row]);
    }
  }
  return groups;
}

export class ReferenceTree implements vscode.TreeDataProvider<Node> {
  private readonly changed = new vscode.EventEmitter<void>();
  readonly onDidChangeTreeData = this.changed.event;
  view?: vscode.TreeView<Node>;

  constructor(private readonly session: Session) {
    session.onDidChange(() => this.refresh());
  }

  refresh(): void {
    this.changed.fire();
  }

  getTreeItem(node: Node): vscode.TreeItem {
    if (node.kind === 'field') {
      const item = new vscode.TreeItem(node.row.field);
      item.contextValue = 'field';
      item.iconPath = new vscode.ThemeIcon(node.row.secret ? 'key' : 'symbol-field');
      item.tooltip = node.row.reference;
      item.command = {
        command: 'octapass.insertField',
        title: vscode.l10n.t('Insert reference'),
        arguments: [node],
      };
      return item;
    }
    const item = new vscode.TreeItem(node.name, vscode.TreeItemCollapsibleState.Collapsed);
    item.iconPath = new vscode.ThemeIcon(node.kind === 'vault' ? 'lock' : 'file');
    return item;
  }

  async getChildren(node?: Node): Promise<Node[]> {
    if (node?.kind === 'field') {
      return [];
    }
    if (node?.kind === 'vault') {
      // By id, since two items can have the same name.
      return [...grouped(node.rows, (row) => row.itemId).values()].map((rows) => ({
        kind: 'item' as const,
        name: rows[0]!.item,
        rows,
      }));
    }
    if (node?.kind === 'item') {
      return node.rows.map((row) => ({ kind: 'field' as const, row }));
    }
    return this.vaults();
  }

  private async vaults(): Promise<Node[]> {
    const view = this.view;
    try {
      const rows = await this.session.rows();
      if (view) {
        view.message = rows?.length === 0 ? vscode.l10n.t('No fields to show.') : undefined;
      }
      return [...grouped(rows ?? [], (row) => row.vault)].map(([name, group]) => ({
        kind: 'vault' as const,
        name,
        rows: group,
      }));
    } catch (error) {
      if (error instanceof ConnectError && error.failure === 'unauthorized') {
        void this.session.report(error);
      } else if (view) {
        view.message = describe(error);
      }
      return [];
    }
  }
}

/** The reference of a field node, for the command the tree runs. */
export function referenceOf(node: unknown): string | undefined {
  const field = node as Extract<Node, { kind: 'field' }> | undefined;
  return field?.kind === 'field' ? field.row.reference : undefined;
}
