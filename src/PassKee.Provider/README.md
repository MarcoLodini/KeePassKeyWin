# PassKee Provider — Build Guide

## Linux / WSL development build

```bash
cargo build          # dev build (Linux, no COM runtime)
cargo test           # runs all non-Windows-runtime tests
```

## Windows cross-compile from Linux (xwin + LLVM)

### 1. Install prerequisites

```bash
# Rust MSVC target
rustup target add x86_64-pc-windows-msvc

# LLVM (lld-link is the linker)
sudo apt-get install lld clang

# xwin — fetches Windows SDK and CRT stubs without a Windows machine
cargo install xwin

# Fetch the SDK into /opt/xwin (matches .cargo/config.toml paths)
sudo xwin --accept-license splat --output /opt/xwin
```

### 2. Build the DLL and CLI

```bash
cargo build --target x86_64-pc-windows-msvc --release
```

Outputs:
- `target/x86_64-pc-windows-msvc/release/passkee_provider.dll`  — COM in-proc server
- `target/x86_64-pc-windows-msvc/release/passkee-provider.exe` — CLI smoke-test tool

### 3. Alternative: MinGW-w64 (no MSVC SDK required)

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

Requires Windows 11 + Windows SDK (makeappx.exe, signtool.exe):

```powershell
# 1. Fill in placeholders in appx/Package.appxmanifest
# 2. Copy assets and binaries into a staging directory
# 3. Package:
makeappx pack /d staging/ /p PassKee.Provider.msix
# 4. Sign (test certificate):
signtool sign /fd sha256 /a PassKee.Provider.msix
```

## Placeholders in Package.appxmanifest

| Placeholder | Replace with |
|---|---|
| `PASSKEE_PUBLISHER_PLACEHOLDER` | `CN=<your cert subject>` |
| `PASSKEE_VERSION_PLACEHOLDER` | `Major.Minor.Build.Revision` e.g. `0.0.1.0` |
