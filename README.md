# PassKee

KeePass 2.x plugin that turns KeePass into a first-class Windows passkey provider.

Create, store, and use FIDO2 / WebAuthn passkeys inside your KeePass vault. Integrated with Windows' Plug-in Authenticator API so any browser or native app on the system can consume them.

## Status

Pre-alpha. Phase 0 scaffolding complete; nothing functional yet. See [`docs/PLAN.md`](docs/PLAN.md).

## Requirements

- **Windows 11 24H2 build 26100.6725+** (November 2025 cumulative update KB5068861 or later). The `IPluginAuthenticator` API did not reach GA before that build — earlier Windows versions are unsupported.
- **KeePass 2.58+** (KeePass 1.x and KeePassXC are not supported).
- **Windows SDK 10.0.26100.7175+** for building the sidecar from source.

## Architecture

Two processes:

- **`PassKee.Plugin`** — .NET Framework 4.8 KeePass plugin. Owns the vault and passkey storage. ECDsa key generation and assertion signing happen here; the private key never leaves this process.
- **`PassKee.Provider`** — Rust MSIX-packaged sidecar. Implements the `IPluginAuthenticator` COM interface. Receives passkey operations from Windows, forwards to the plugin over a named pipe, encodes the response.

The two-process split is forced by Windows: `IPluginAuthenticator` must be registered via an AppX manifest, and KeePass is an unpackaged .NET Framework app that cannot host a packaged COM server.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full picture.

## Non-goals for v1

Deferred to future versions:

- **Enterprise attestation / real AAGUID.** PassKee uses `none` attestation with an all-zero AAGUID. Some enterprise RPs (Azure AD conditional access, some banks) blocklist all-zero AAGUIDs and will reject PassKee passkeys.
- **`hmac-secret` / `prf` extension.** Used by a handful of advanced password-manager flows. Not required for mainstream passkey login.
- **Multiple KeePass instances with different vaults.** v1 is single-instance-per-session. A second KeePass process is detected and stays passive.

## Building

Not yet wired up. Build instructions will land alongside Phase 1.

## License

GPL-3.0-or-later. See [`LICENSE`](LICENSE).
