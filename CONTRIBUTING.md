# Contributing to PassKee

Thanks for your interest in PassKee! This guide covers everything you need to build, test, and submit changes.

PassKee is pre-1.0 software and the surface area is unusual — a .NET Framework 4.8 KeePass plugin, a Rust MSIX-packaged COM server, a named-pipe IPC protocol, and live Windows Plug-in Authenticator integration. Expect the build to need more than "clone and go". This document tries to make that cost explicit.

## Before you start

- Read [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the two-process design and why it is structured the way it is.
- Read [`docs/PLAN.md`](docs/PLAN.md) for current phase status, deferred items, and post-v1 goals. Ongoing work lives there.
- For anything WebAuthn / CTAP2 / Windows Plug-in Authenticator wire-level, [`docs/IPC_PROTOCOL.md`](docs/IPC_PROTOCOL.md) and [`docs/SPECS.md`](docs/SPECS.md) are the sources of truth.
- By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
- Security issues go through [`SECURITY.md`](SECURITY.md), **not** public issues.

## Licensing

PassKee is **GPL-3.0-or-later** (see [`LICENSE`](LICENSE)). Contributions are accepted under the same license. By opening a pull request you certify that you have the right to license your contribution under GPL-3.0-or-later.

Third-party code must be compatible with GPL-3.0-or-later and attributed in [`THIRD_PARTY_LICENSES`](THIRD_PARTY_LICENSES).

## Development environment

### Supported host OSes

| Host | What you can do |
|---|---|
| Windows 11 24H2 build 26100.6725+ | Everything — build, unit tests, plugin install, MSIX pack + sign, live browser validation. |
| Linux / WSL2 | Unit tests for both stacks, Rust cross-compile for Windows via `cargo xwin`. Cannot run the plugin or do live validation. |
| macOS | .NET and Rust unit tests only. |

### Toolchain

- **.NET SDK 8.0** — build + test driver for both csproj targets. `dotnet --version` must report `8.x`. Note that the plugin itself targets `net48` at runtime (KeePass hosts it), while the harness and tests target `net8.0`.
- **Rust stable** (current MSRV: whatever `rustup default stable` gives you). The sidecar lives in `src/PassKee.Provider/`.
- **Windows SDK 10.0.26100.7175+** — only needed if you build the MSIX or run live validation on Windows.
- **`cargo xwin`** — only needed to cross-compile the Windows sidecar from Linux/WSL. Install with `cargo install cargo-xwin`; also needs the `lld` and `clang` system packages.
- **KeePass 2.58+** — only needed for live validation; never for tests.

## Build

### .NET (cross-platform)

```bash
dotnet restore PassKee.sln
dotnet build PassKee.sln --no-restore
```

The plugin assembly (`src/PassKee.Plugin`) targets `net48` and references KeePass's `KeePass.exe` as an assembly reference. On Linux the reference is stubbed via `KeePassDir` MSBuild properties; for a real install on Windows you need an actual KeePass install path:

```powershell
dotnet build src/PassKee.Plugin -f net48 /p:KeePassDir="C:\Program Files\KeePass Password Safe 2"
```

### Rust sidecar

From `src/PassKee.Provider/`:

```bash
cargo build                       # host-native (Linux/macOS) — tests only
cargo xwin build --target x86_64-pc-windows-msvc --release   # Windows artifact from WSL
```

On Windows directly:

```powershell
cargo build --target x86_64-pc-windows-msvc --release
```

## Tests

CI runs both of these on Ubuntu on every PR. Run them locally before pushing.

### .NET unit tests

```bash
dotnet test PassKee.sln --nologo
```

(CI adds `--no-restore` because it runs an explicit restore step first; for a cold local run, let `dotnet test` restore implicitly.)

Runs cross-platform. Exercises CBOR encoding, COSE key layout, authData construction, JSON-RPC framing, crypto round-trips, and the in-memory passkey store.

### Rust unit + integration tests

```bash
cd src/PassKee.Provider
cargo test --all-targets
```

`--all-targets` is important — the default `cargo test` skips integration tests under `tests/` which cover the COM/FFI layer and CBOR shape canaries. Don't rely on the shortcut.

### Live Windows validation

Unit tests are not enough for runtime-behavior changes. If your PR touches the plugin IPC, the Rust sidecar, the COM interface, or authData / signature layout, you **must** validate end-to-end against a real browser. The runbook is [`docs/WINDOWS_VALIDATION.md`](docs/WINDOWS_VALIDATION.md).

Minimum gate for a runtime PR:

1. `dotnet test` green.
2. `cargo test --all-targets` green.
3. The right phase-specific validator green on Windows — match the layer your PR touches:
   - Plugin / IPC / crypto (Phase 0.5 surface) → `scripts/validate-phase05.ps1`.
   - MSIX packaging or install flow → `scripts/validate-phase2.ps1`.
   - Rust sidecar / COM activation / Plug-in Authenticator registration → `scripts/validate-phase22.ps1`.
4. Manual registration + login at `https://webauthn.io` from Edge or Chrome, against a Win11 build ≥ 26100.6725.

Call the Windows build, browser, and RP out in your PR description.

## Style and conventions

- **C#**: follow what's already there. `dotnet format` if you're unsure. Public APIs stay stable across phases; breaking changes need a note in [`docs/PLAN.md`](docs/PLAN.md).
- **Rust**: `cargo fmt` and `cargo clippy --all-targets -- -D warnings` should be clean before you push. No `unsafe` without a comment explaining the invariant.
- **Comments**: default to none. When you do write one, explain *why*, not *what*. If a non-obvious constraint bit you (an off-by-one in a CBOR header, a Windows API that silently fails on a wrong struct size, a hidden ABI requirement), leave a comment so the next person doesn't re-discover it.
- **Docs**: update the relevant doc in the same PR as the code change. `docs/PLAN.md` tracks what shipped in which phase; keep it current.
- **Dependencies**: adding a dependency is a non-trivial change. Prefer the standard library. If a new dep is required, note the license in the PR description and check [`THIRD_PARTY_LICENSES`](THIRD_PARTY_LICENSES).

## Commits

- **Conventional Commits** style — `feat(scope): …`, `fix(scope): …`, `chore(scope): …`, `docs(scope): …`. Look at recent history (`git log --oneline`) for examples.
- **Signed commits are preferred** (GPG or SSH). Not a hard requirement, but a strong norm given what PassKee brokers.
- **Small, focused commits** beat a single mega-commit. Squash-merge is the default strategy at merge time, so the commit boundary within a PR is for review ergonomics.
- **No secrets, no credentials.** `.env`, `.pfx`, `.snk`, `cert-thumbprint.txt`, vault files — never committed. The repo root `.gitignore` covers the usual suspects; double-check your diff.

## Pull requests

1. Fork the repo and branch off `master`. Keep one logical change per PR.
2. Write tests. New CBOR parsing / Windows API binding / crypto code without tests will be asked to add them before review.
3. If your change is runtime-behavior (plugin, sidecar, IPC, COM), include a live-validation note in the PR description — Windows build, browser, RP, and what flow you exercised.
4. Fill out the PR template. The "Test plan" section is not optional.
5. Ensure CI is green. CI runs on `ubuntu-latest` and covers both stacks; a red CI will block review.
6. Expect review comments. PassKee has narrow tolerances — a COSE key with the wrong integer type, a CTAP2 response with text keys instead of integer keys, a signCount written asynchronously — all of these have produced silent runtime failures in the past. Reviewers will push on this kind of detail; it is not personal.

## Landmines

Some constraints are not obvious from the code. [`docs/PLAN.md`](docs/PLAN.md) and the per-session close-out notes in `memory/sessions/` (if present in your clone's memory directory) document landmines the team has hit. Skim them before changing:

- CBOR shape — CTAP2 top-level maps are **integer-keyed**, nested `PublicKeyCredentialDescriptor` is **text-keyed**. Getting this wrong produces errors the browser surfaces as "security error" with no diagnostic.
- `signCount` persistence must be **synchronous** (`PwDatabase.Save` on every increment). Asynchronous save can roll the counter backward on a hard KeePass close, which an RP interprets as a cloned authenticator per WebAuthn §6.1.1.
- Windows `WEBAUTHN_PLUGIN_*` structs have specific x64 offsets. The Rust code carries `offset_of!` assertions — don't remove them.
- Settings UI — plugin-managed credentials do **not** appear under Settings → Accounts → Passkeys (that list is Windows-Hello-only). They live in the provider's own UI. Not a bug.

## Questions

Open a GitHub Discussion for design questions or an issue with the `question` label for narrower clarifications. For anything security-adjacent, prefer the private-disclosure channel in [`SECURITY.md`](SECURITY.md).

Thanks for contributing!
