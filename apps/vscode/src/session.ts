// The token, kept only in SecretStorage, and what each answer from Connect means for the person.

import { homedir } from 'node:os';
import * as vscode from 'vscode';
import { ConnectClient, ConnectError, findEndpoint } from './connect';
import { fieldRows, type FieldRow } from './references';

const TOKEN = 'octapass.connect.token';
const CLIENT_NAME = 'VS Code';

function openClient(token?: string): ConnectClient {
  return new ConnectClient(findEndpoint({ env: process.env, platform: process.platform, home: homedir() }), token);
}

/** What to tell the person. `connect` errors offer to connect again instead. */
export function describe(error: unknown): string {
  if (!(error instanceof ConnectError)) {
    return vscode.l10n.t('Octa Pass Connect refused this request.');
  }
  switch (error.failure) {
    case 'not-running':
      return vscode.l10n.t("Octa Pass Connect isn't running. Start it with octapass connect serve, or turn it on in the desktop app.");
    case 'bad-endpoint':
      return vscode.l10n.t("OCTAPASS_CONNECT isn't a valid address. Use unix:/path/to/connect.sock or http://127.0.0.1:<port>.");
    case 'locked':
      return vscode.l10n.t('Octa Pass is locked. Unlock it, then try again.');
    case 'unauthorized':
      return vscode.l10n.t('The connection to Octa Pass has ended. Connect again to keep using it.');
    case 'denied':
      return vscode.l10n.t("The request wasn't approved.");
    case 'busy':
      return vscode.l10n.t('Another program is waiting for approval. Try again in a moment.');
    case 'timed-out':
      return vscode.l10n.t("Octa Pass Connect didn't answer in time.");
    case 'bad-response':
      return vscode.l10n.t("Octa Pass Connect sent an answer this version can't read.");
    default:
      return error.status
        ? vscode.l10n.t("Octa Pass Connect couldn't do that: {0}", error.message)
        : vscode.l10n.t('Octa Pass Connect refused this request.');
  }
}

export class Session implements vscode.Disposable {
  private readonly changed = new vscode.EventEmitter<void>();
  private readonly watcher: vscode.Disposable;
  readonly onDidChange = this.changed.event;

  constructor(private readonly secrets: vscode.SecretStorage) {
    this.watcher = secrets.onDidChange(({ key }) => {
      if (key === TOKEN) {
        void this.publish();
      }
    });
  }

  dispose(): void {
    this.watcher.dispose();
    this.changed.dispose();
  }

  /** Sets the `octapass.connected` context and tells the tree. */
  async publish(): Promise<void> {
    await vscode.commands.executeCommand('setContext', 'octapass.connected', Boolean(await this.secrets.get(TOKEN)));
    this.changed.fire();
  }

  private async setToken(token: string | undefined): Promise<void> {
    await (token ? this.secrets.store(TOKEN, token) : this.secrets.delete(TOKEN));
    await this.publish();
  }

  /** The rows of the vaults, or `undefined` if there's no token. */
  async rows(): Promise<FieldRow[] | undefined> {
    const token = await this.secrets.get(TOKEN);
    if (!token) {
      return undefined;
    }
    try {
      return fieldRows(await openClient(token).items());
    } catch (error) {
      if (error instanceof ConnectError && error.failure === 'unauthorized') {
        await this.setToken(undefined);
      }
      throw error;
    }
  }

  async connect(): Promise<void> {
    try {
      if (await this.rows()) {
        void vscode.window.showInformationMessage(vscode.l10n.t('Already connected to Octa Pass.'));
        return;
      }
    } catch (error) {
      // A token that no longer works is gone by now, so ask for a new one. Anything else stands.
      if (!(error instanceof ConnectError && error.failure === 'unauthorized')) {
        await this.report(error);
        return;
      }
    }
    try {
      const paired = await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: vscode.l10n.t('Waiting for approval in Octa Pass…'),
          cancellable: true,
        },
        (_progress, cancellation) => {
          const stop = new AbortController();
          cancellation.onCancellationRequested(() => stop.abort());
          return openClient().pair(CLIENT_NAME, stop.signal);
        },
      );
      await this.setToken(paired.token);
      void vscode.window.showInformationMessage(vscode.l10n.t('Connected to Octa Pass.'));
    } catch (error) {
      await this.report(error);
    }
  }

  async disconnect(): Promise<void> {
    const token = await this.secrets.get(TOKEN);
    let revoked = true;
    if (token) {
      try {
        await openClient(token).forget();
      } catch (error) {
        // Unauthorized means Connect has already let go of it.
        revoked = error instanceof ConnectError && error.failure === 'unauthorized';
      }
    }
    await this.setToken(undefined);
    void vscode.window.showInformationMessage(
      revoked
        ? vscode.l10n.t('Disconnected from Octa Pass.')
        : vscode.l10n.t("Disconnected here. Octa Pass Connect couldn't be reached, so the token stays valid until it expires."),
    );
  }

  /** Shows an error, and offers to connect when that's the way out. */
  async report(error: unknown): Promise<void> {
    if (error instanceof ConnectError && error.failure === 'cancelled') {
      return;
    }
    if (error instanceof ConnectError && error.failure === 'unauthorized') {
      await this.setToken(undefined);
      await this.offerConnect(describe(error));
      return;
    }
    void vscode.window.showErrorMessage(describe(error));
  }

  async offerConnect(message: string): Promise<void> {
    const connect = vscode.l10n.t('Connect');
    if ((await vscode.window.showWarningMessage(message, connect)) === connect) {
      await this.connect();
    }
  }
}
