# OpenLXSSH

[简体中文](README.md) · **English**

OpenLXSSH is a lightweight, native **SSH and SFTP client for Apple Silicon Macs**. It runs on M-series chips with **macOS 26 or later**. The desktop app uses SwiftUI and AppKit, with no Electron runtime or cloud account required.

## Download the trial

[Download the Apple Silicon DMG](https://github.com/chunqiu007/OpenLXSSH/releases/download/v1.0.0-trial.2026110501/OpenLXSSH-Trial-1.0.0-2026110501-arm64.dmg) · [Release notes](https://github.com/chunqiu007/OpenLXSSH/releases/tag/v1.0.0-trial.2026110501)

Open the DMG for **1.0.0 (build 2026110501)**, drag the app into Applications, then launch it from Applications. The trial was signed offline with Developer ID. Apple notarization is still outstanding, so Gatekeeper may block it on another Mac. If that happens, include the exact macOS message in your feedback.

## Memory usage

On an Apple Silicon Mac, the earlier **1.0.0 build 3** measured about **107–111 MiB** of resident memory (RSS) at idle. With **five simultaneous SSH sessions**, the app and its SSH processes averaged **125.1 MiB** combined. The peak was **135.4 MiB** while producing terminal output and switching tabs. The current trial is a later build, and these measurements apply to build 3. [Measurement details](docs/reports/mac26-takeover.md)

## What you can do

- Organize hosts with groups, tags, and favorites, and keep independent SSH sessions open in tabs.
- Sign in with a password or SSH key and respond to server prompts such as MFA. Save supported credentials in macOS Keychain and verify host fingerprints when connecting.
- Browse local and remote folders side by side over SFTP, transfer files and folders, and manage progress and name conflicts.
- Connect to a jump host and run a second `ssh` command manually in its terminal. The SFTP browser connects directly to its target server.

## Help test OpenLXSSH

1. Install and launch the trial on an M-series Mac. Add a host you have permission to test, verify its fingerprint, and try the authentication method you normally use.
2. Open and switch between terminal tabs. If you use a jump host, try your regular nested SSH workflow.
3. Upload and download a small test file in SFTP. Try a same-name transfer and check that **Cancel**, **Replace**, and **Keep Both** behave as you expect.

When reporting an issue, include your Mac chip, macOS version, app build, reproduction steps, and expected and actual behavior. Remove passwords, private keys, one-time codes, and real host details from logs and screenshots. [Open a GitHub issue](https://github.com/chunqiu007/OpenLXSSH/issues/new)
