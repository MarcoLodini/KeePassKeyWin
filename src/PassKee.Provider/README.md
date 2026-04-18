# PassKee Provider — Build Guide

## Linux / WSL development build

```bash
cargo build          # dev build (Linux, no COM runtime)
cargo test           # runs all non-Windows-runtime tests
```

## Windows cross-compile from Linux/WSL2 (cargo-xwin)

`cargo-xwin` handles the Windows SDK and CRT download automatically — no
`sudo`, no manual splatting, no `/opt/xwin`. The SDK is cached in
`~/.cache/cargo-xwin/` on first use.

### 1. Install prerequisites

```bash
# Rust MSVC target
rustup target add x86_64-pc-windows-msvc

# LLVM linker + clang (used by cargo-xwin internally)
sudo apt-get install lld clang

# cargo-xwin — self-managed Windows SDK cache
cargo install cargo-xwin
```

### 2. First build (downloads ~1 GB of SDK on first invocation)

```bash
cargo xwin build --target x86_64-pc-windows-msvc --release
```

`cargo-xwin` downloads and unpacks the Windows SDK and CRT stubs into
`~/.cache/cargo-xwin/xwin/` on first invocation. Subsequent builds reuse
the cache and are fast.

Outputs:
- `target/x86_64-pc-windows-msvc/release/passkee_provider.dll`  — COM in-proc server
- `target/x86_64-pc-windows-msvc/release/passkee-provider.exe` — CLI smoke-test tool

### 3. Verifying the DLL

```bash
file target/x86_64-pc-windows-msvc/release/passkee_provider.dll
# → PE32+ executable (DLL) (GUI) x86-64, for MS Windows ...
```

### 4. Alternative: MinGW-w64 (no MSVC SDK required)

MinGW-w64 works for pure Rust code but may have issues with MSVC COM ABI details.
Use it only for quick iteration, not for production builds.

```bash
rustup target add x86_64-pc-windows-gnu
sudo apt-get install gcc-mingw-w64-x86-64
cargo build --target x86_64-pc-windows-gnu --release
```

## Windows native build (on a Windows 11 machine)

```powershell
rustup target add x86_64-pc-windows-msvc
cargo build --target x86_64-pc-windows-msvc --release
```

## MSIX packaging (Windows only)

Requires Windows 11 + Windows SDK (`makeappx.exe`, `signtool.exe`). The
placeholders in `appx/Package.appxmanifest` are pre-filled for the PassKee
dev cert (`CN=Marco Lodini, O=PassKee, C=IT`, Version `0.0.1.0`); see
`docs/WINDOWS_VALIDATION.md` if you need to change them.

One-command flow (builds MSIX → signs → installs → verifies):

```powershell
.\scripts\validate-phase2.ps1
```

Or run the steps individually:

```powershell
.\scripts\ensure-dev-cert.ps1   # first run only (needs admin); creates + trusts cert
.\scripts\build-msix.ps1        # stages DLL + EXE + Assets\, runs makeappx
.\scripts\sign-msix.ps1         # Publisher/Subject pre-check, then signtool
.\scripts\install-msix.ps1      # Add-AppxPackage + Get-AppxPackage assertion
```

Outputs land in `out\` (gitignored): `PassKee.Provider.msix`, `PassKee.Dev.pfx`,
`cert-thumbprint.txt`.

### Rollback

```powershell
Remove-AppxPackage -Package (Get-AppxPackage -Name PassKee.Provider).PackageFullName
$tp = Get-Content .\out\cert-thumbprint.txt
Remove-Item "Cert:\CurrentUser\My\$tp"
Remove-Item "Cert:\LocalMachine\TrustedPeople\$tp"
```
