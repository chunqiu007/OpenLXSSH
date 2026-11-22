# OpenLXSSH

[简体中文](README.md) · **English**

OpenLXSSH is a lightweight, native **SSH and SFTP client for Apple Silicon Macs**. It runs on M-series chips with **macOS 26 or later**. The desktop app uses SwiftUI and AppKit, with no Electron runtime or cloud account required.

## Download Release 2.5

[Download the Apple Silicon DMG](https://github.com/chunqiu007/OpenLXSSH/releases/download/v2.5/OpenLXSSH-2.5-arm64.dmg) · [Release notes](https://github.com/chunqiu007/OpenLXSSH/releases/tag/v2.5)

Open the DMG, drag OpenLXSSH into Applications, and launch it from there. The image contains app version **2.5 (build 8)**. It is signed offline with Developer ID and has not been notarized by Apple.

When upgrading from 2.0.4, saved passwords and key passphrases do not migrate automatically to the new Keychain storage. To save a password again, edit its host in the vault. To save a passphrase again, select its key in the keys and credentials view.

## Memory usage

On an Apple Silicon Mac, the earlier **1.0.0 build 3** measured about **107–111 MiB** of resident memory (RSS) at idle. With **five simultaneous SSH sessions**, the app and its SSH processes averaged **125.1 MiB** combined. The peak was **135.4 MiB** while producing terminal output and switching tabs. These measurements are from the October 30, 2026 build (full historical report archived at Git tag `v2.0.4`).

## What you can do

- Organize hosts with groups, tags, and favorites, and keep independent SSH sessions open in tabs. Version 2.5 supports native terminal split panes (`⌘D` / `⇧⌘D`) and multi-window workspaces (`⌘N`).
- Sign in with a password or SSH key and respond to server prompts such as MFA. Save supported credentials in the local macOS Keychain and verify host fingerprints when connecting.
- Browse local and remote folders side by side over SFTP, transfer files and folders, and manage progress and name conflicts.
- Connect to a jump host and run a second `ssh` command manually in its terminal. The SFTP browser connects directly to its target server.

See [User Guide](docs/user-guide.md) and [Architecture](docs/architecture.md) (Chinese) for full details.

## Help test OpenLXSSH

1. Install and launch Release 2.5 on an M-series Mac. Add a host you have permission to test, verify its fingerprint, and try the authentication method you normally use.
2. Open and switch between terminal tabs. If you use a jump host, try your regular nested SSH workflow.
3. Upload and download a small test file in SFTP. Try a same-name transfer and check that **Cancel**, **Replace**, and **Keep Both** behave as you expect.

When reporting an issue, include your Mac chip, macOS version, app build, reproduction steps, and expected and actual behavior. Remove passwords, private keys, one-time codes, and real host details from logs and screenshots. [Open a GitHub issue](https://github.com/chunqiu007/OpenLXSSH/issues/new)
