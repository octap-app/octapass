---
title: SSH keys
description: Keep SSH keys in Octa Pass, generate Ed25519, ECDSA or RSA keys, import OpenSSH, PEM and PKCS#8 files, and export private and public keys safely.
status: in-progress
sidebar:
  order: 18
---

:::note[In progress]
SSH keys work in the web vault, the desktop app, the [CLI](/docs/platforms/cli/) and the native iPhone, iPad and Android apps, and the desktop app has the [SSH agent](#ssh-agent) and [`~/.ssh`](#ssh-on-this-computer). The browser extension shows keys but can only copy their public parts. The agent has been tested with the real OpenSSH tools on macOS; its Touch ID prompts, Windows and Linux haven't been tried on real machines yet.
:::

An **SSH key** is its own item type, with its own category in the sidebar and its own section when a list is grouped by type. Like every item, it's encrypted on your device: the server never sees the private key, the public key, the fingerprint or the comment.

## What a key holds

| Field | Notes |
|---|---|
| **Private key** | In OpenSSH format, stored **without a passphrase**: the vault encrypts it. Shown or copied only after you've unlocked with your master password or device unlock, or confirmed it again; saved to a file only after you confirm it again. |
| **Public key** | `ssh-ed25519 AAAA…`, without the comment. This is what you put on a server. |
| **Key type** | The SSH algorithm (`ssh-ed25519`, `ecdsa-sha2-nistp256`, `ssh-rsa`, …), shown to people as Ed25519, ECDSA P-256 and so on. |
| **Fingerprint** | `SHA256:…`, the same as `ssh-keygen -l -E sha256` prints. It's the list's subtitle and tells keys apart. |
| **Comment** | Usually `you@computer`; it ends the `authorized_keys` line. Servers ignore it. |
| **Passphrase** | Optional. Protects copies you export; the key in the vault is protected by the vault itself. |
| **Notes** and fields | Like any item. |

## Generate

Choose **New SSH key**, then a key type and **Generate**:

- **Ed25519** works with almost every current server and is the recommendation.
- **ECDSA P-256** and **P-384** for servers that ask for those curves.
- **RSA 3072** or **RSA 4096** for old servers that don't support Ed25519. RSA is slower and larger; prefer Ed25519 where you can.

The key is made on the device by the Octa Pass core. The private key never leaves it unencrypted. Prefer Ed25519. RSA keys work too: they're signed with `ring`, not the `rsa` crate, because of an [open timing advisory](#rsa-keys).

## Import

Import a private key file, or paste its text:

- **OpenSSH** private keys (`-----BEGIN OPENSSH PRIVATE KEY-----`), with or without a passphrase.
- **PEM** keys: PKCS#1 RSA (`RSA PRIVATE KEY`), SEC1 EC (`EC PRIVATE KEY`) and DSA (`DSA PRIVATE KEY`).
- **PKCS#8** keys (`PRIVATE KEY`, and `ENCRYPTED PRIVATE KEY`), plain or passphrase-protected.

Octa Pass asks for a passphrase when the file has one, then reads the public key, type and fingerprint from the private key. Choose the file **without** `.pub`: a public key can't be turned into a private one, and the app says so.

Some keys are kept but can't be used yet:

- **DSA** keys and **FIDO** security-key (`sk-`) keys are stored with their public key and fingerprint. They can't be generated, used or converted in this version.
- **PuTTY** (`.ppk`) keys and keys encrypted with **3DES** aren't read. Convert them with `ssh-keygen` first.

Malformed files, a wrong passphrase and unsupported formats each get a clear message instead of a broken item.

## View and copy

The item shows the public key, fingerprint, type and comment. Copy the public key from the item or, in the browser extension, from the list row. The **private key** stays hidden until you choose **Show**. If you unlocked Octa Pass with your master password or device unlock, that's enough; otherwise it asks you to confirm it's you (see [Revealing and copying](/docs/features/biometric-unlock/#revealing-and-copying)). Exporting the private key asks every time.

The extension shows SSH key items, their fingerprint and a copy button for the public key only. It never reads or shows the private key.

## Export

- **Save private key** writes an OpenSSH file. Choose a passphrase for the file or leave it empty. If the item has a passphrase saved, it's offered by default.
- **Save public key** writes the `authorized_keys` line (the key and its comment).

The [CLI](/docs/platforms/cli/#ssh-keys) writes private keys readable only by you (mode `0600`) and won't replace an existing file without `--force`.

## Move keys between apps

Octa Pass's own export and the [Credential Exchange Format](/docs/import-export/from-cxf/) (CXF) carry `sshKey` items losslessly. When Octa Pass exports CXF, the key is written as an `ssh-key` credential with its private key in PKCS#8 and an optional passphrase custom field. Importing such a file turns it back into an SSH key item. DSA and FIDO keys can't be converted to CXF and are reported as left out.

## SSH agent

The desktop app can act as your SSH agent, so `ssh`, Git and IDEs use the keys in your vault without a copy on disk.

1. In **Settings → SSH agent**, turn on **Run the SSH agent**. It's off until you do, and the choice is for this computer only.
2. Choose **Use it for SSH**, which adds a marked block to the end of `~/.ssh/config`, so hosts with their own `IdentityAgent` keep it. Or set it for one terminal: `export SSH_AUTH_SOCK=~/.octapass/agent.sock`.

Then `ssh-add -l` lists your keys and `ssh` just works.

- **You approve each use.** Every signature asks Touch ID, Windows Hello or your system password, naming the key, what it's for and the program asking. Cancelling refuses it. A computer with no lock shows an Allow / Deny window instead.
- **Only while unlocked.** A request to a locked vault opens the device unlock prompt. If you cancel, or device unlock isn't on, the agent offers nothing for a minute, so tools that poll it don't keep asking.
- **It only lists and signs.** `ssh-add` can't add or remove keys: the vault owns them.
- **Fewer keys:** servers stop after about six tries, so with many keys, untick **Offer this key through the SSH agent** in a key's editor.
- **Git:** `octapass git setup --signing-key <key> --agent` signs commits through the agent, or set `gpg.format = ssh` and `user.signingkey = key::<public key>` yourself. See [the CLI](/docs/platforms/cli/#git).
- **Forwarding** (`ssh -A`) works and each use still asks you, but the prompt names your local `ssh`, not the remote program.

On the **Mac** the app is sandboxed, so the agent's socket is in the app's own folder, `~/Library/Group Containers/<team>.app.octap/agent.sock`, and Octa Pass doesn't edit `~/.ssh/config` for you. Settings → SSH agent shows the path with a copy button, and the lines to add to `~/.ssh/config` (the path has a space, so keep the quotes):

```text
Host *
  IdentityAgent "~/Library/Group Containers/<team>.app.octap/agent.sock"
```

Or for one terminal: `export SSH_AUTH_SOCK="$HOME/Library/Group Containers/<team>.app.octap/agent.sock"`. `<team>` is the Apple team that signed the app; Settings shows the full path.

On **Windows** the agent uses the `openssh-ssh-agent` pipe that Windows' `ssh.exe` looks for. Only one agent can have it, so stop the **OpenSSH Authentication Agent** service first; Settings shows the error if it's taken.

### RSA keys

The `rsa` crate has an open advisory, [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071) (the Marvin attack), a timing leak in private-key operations. It was still unpatched when we last checked on 2 November 2026, in 0.9.10 and in 0.10.0-rc.19. So Octa Pass never signs with that crate: RSA signatures go through [`ring`](https://github.com/briansmith/ring), which is constant-time. Only `rsa-sha2-256` and `rsa-sha2-512` signatures are made; the old SHA-1 `ssh-rsa` is refused, so a server too old for SHA-2 won't accept your RSA key. RSA OpenPGP keys can't sign at all, because that library has no such option.

## ~/.ssh on this computer

In the desktop app, the key editor lists the private keys already in `~/.ssh`: choose one to bring it in, with its passphrase if it has one. On a saved key, **Write to ~/.ssh** writes the private key (readable only by you) and its `.pub` file, after you confirm it's you. It never replaces a file unless you tick that box. Neither happens by itself: Octa Pass doesn't watch or sync the folder.

## Not yet

- Native iOS and Android screens.
- Mapping other managers' imports (Bitwarden, Proton Pass, 1PUX, Keeper) to the SSH key type; for now they still arrive as secure notes. CXF is the exception.
