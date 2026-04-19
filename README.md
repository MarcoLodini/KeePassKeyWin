# PassKee

KeePass 2.x plugin that turns KeePass into a first-class Windows passkey provider.

Create, store, and use FIDO2 / WebAuthn passkeys inside your KeePass vault. Integrated with Windows' Plug-in Authenticator API so any browser or native app on the system can consume them.

## Status

Pre-release. End-to-end passkey register and login work on Windows 11 25H2 (build 26200.8037) with real browser sessions at webauthn.io — 220 .NET and 54 Rust tests all green. There is no signed MSIX installer or packaged distribution yet; this is developer-accessible code, not a product release. See [`docs/PLAN.md`](docs/PLAN.md) for phased progress and [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the design.

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

- **Enterprise attestation / AAGUID allowlists.** PassKee uses `none` attestation with a fixed, randomly-generated project-wide AAGUID (`a97d1e2b-4c8f-4a3e-9bd6-5f82c1476e3d`) — stable across installs, but not per-install unique and not backed by an attestation certificate chain. Some enterprise RPs (Azure AD conditional access, some banks) enforce AAGUID allowlists of certified authenticators and will reject PassKee passkeys until/unless its AAGUID is added to their allowlist.
- **`hmac-secret` / `prf` extension.** Used by a handful of advanced password-manager flows. Not required for mainstream passkey login.
- **Multiple KeePass instances with different vaults.** v1 is single-instance-per-session. A second KeePass process is detected and stays passive.

## Try it on Windows (Phase 0.5 developer harness)

> Phase 0.5 scope: no MSIX, no Rust sidecar — this exercises the crypto,
> storage, and IPC layers against a real KeePass instance and a real browser.

See **[`docs/WINDOWS_VALIDATION.md`](docs/WINDOWS_VALIDATION.md)** for the full step-by-step runbook.

**Developer-validation only — not the end-user install flow.** The commands below exercise the Phase 0.5 smoke-test harness; they do not install a working passkey provider. The full end-user install path (signed MSIX, passkey provider registration) is the Phase 6 distribution milestone and is not yet available.

Quick start:

```powershell
# Build and install the plugin into KeePass
.\scripts\build-plugin.ps1 -KeePassDir "C:\Program Files\KeePass Password Safe 2"

# Run the smoke test (start KeePass and open a .kdbx first)
.\scripts\smoke-test.ps1
```

## Building

### Plugin (net48, Windows only)

```powershell
dotnet build src/PassKee.Plugin -f net48 /p:KeePassDir="C:\Program Files\KeePass Password Safe 2"
```

### Harness (net8.0, cross-platform build, Windows execution)

```powershell
dotnet build src/PassKee.Harness -c Release
```

### Unit tests (net8.0, Linux/macOS/Windows)

```bash
dotnet test --nologo
```

## License

GPL-3.0-or-later. See [`LICENSE`](LICENSE).
