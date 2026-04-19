# PassKee Windows Validation Runbook

> **v0.1 pre-release — expect churn.** This runbook validates Phase 0.5
> (crypto + storage + IPC) end-to-end against a real KeePass + real Chrome
> without any Rust sidecar or MSIX packaging. Treat every step as provisional;
> the exact commands will stabilise once Phase 1 hardens.

---

## Prerequisites

| Requirement | Minimum |
|---|---|
| Windows version | Windows 11 24H2 build **26100.6725** or newer (verify: `winver`) |
| KeePass | 2.58 or newer — <https://keepass.info/download.html> |
| .NET Framework | 4.8 (ships with Win11 — confirm via `reg query "HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" /v Release`) |
| .NET SDK | 8.0 — <https://dot.net> (`dotnet --version` must show `8.x`) |
| Chrome or Edge | Any recent stable build |
| Playwright Chromium | Run once: `dotnet tool install --global Microsoft.Playwright.CLI && playwright install chromium` |

All build and harness commands run in a **PowerShell 7** prompt opened from the repo root.

---

## Unattended validator (Steps 1–5 + 7)

If you just want to confirm Phase 0.5 end-to-end without running through each
step by hand, run the consolidated validator:

```powershell
.\scripts\validate-phase05.ps1
```

It pre-flights prerequisites, builds + installs the plugin, creates a throwaway
vault from `scripts\fixtures\template.kdbx`, launches KeePass, runs the smoke
test, verifies nonce teardown, and reports `PASS` / `FAIL: <reason>` with a
diagnostic bundle. Chrome is no longer required for smoke mode (Phase 2.1
decoupling). It does **not** cover Step 6 (browser scenario with webauthn.io)
— that still requires manual gestures; run the steps below for that.

Use `-DryRun` to run pre-flight only, or `-KeepTempFiles` to preserve the
throwaway vault for debugging.

---

## Step 1 — Build the plugin

```powershell
# Replace the path if KeePass is installed elsewhere.
$KeePassDir = "C:\Program Files\KeePass Password Safe 2"
dotnet build src/PassKee.Plugin -f net48 /p:KeePassDir="$KeePassDir"
```

Expected: `Build succeeded. 0 Error(s)` and output at
`src\PassKee.Plugin\bin\Debug\net48\PassKee.dll`.

If you prefer the automated script:

```powershell
.\scripts\build-plugin.ps1 -KeePassDir $KeePassDir
# Use -DryRun to preview without copying.
```

---

## Step 2 — Build the harness

```powershell
dotnet build src/PassKee.Harness -c Release
```

Harness binary: `src\PassKee.Harness\bin\Release\net8.0\PassKee.Harness.exe`

---

## Step 3 — Install the plugin into KeePass

Copy `PassKee.dll` and its dependency `Newtonsoft.Json.dll` into the KeePass
`Plugins\` folder:

```powershell
.\scripts\build-plugin.ps1 -KeePassDir $KeePassDir
```

Or manually:

```powershell
$src    = "src\PassKee.Plugin\bin\Debug\net48"
$target = "$KeePassDir\Plugins"
Copy-Item "$src\PassKee.dll"         $target -Force
Copy-Item "$src\Newtonsoft.Json.dll" $target -Force
```

> **Architecture must match.** KeePass 2.x ships as 32-bit (x86) by default.
> `PassKee.Plugin` targets AnyCPU, so it adapts — but if you see a
> `BadImageFormatException` in the KeePass log, confirm KeePass's
> bitness with `(Get-Item "$KeePassDir\KeePass.exe").Headers.Machine`.

---

## Step 4 — First-run checks in KeePass

1. Close KeePass if it is running, then start it again.
2. Open or create a test `.kdbx` file (do **not** use your real vault).
3. Click **Tools** in the menu bar.
   - You should see a **PassKee** submenu.
   - Click **OS compatibility...** — it should report "Your OS meets PassKee requirements."
4. Check the KeePass status bar (bottom) — it should not show any PassKee error.
5. Confirm the handshake nonce was written to the registry:

```powershell
Get-ItemProperty HKCU:\Software\PassKee -Name HandshakeNonce
```

You should see a 64-character hex string.

---

## Step 5 — Run the smoke test

The `scripts\smoke-test.ps1` script finds the session ID and nonce automatically,
then calls the harness in `--smoke` mode.

```powershell
.\scripts\smoke-test.ps1
```

Or manually:

```powershell
$sessionId = (Get-Process KeePass -ErrorAction Stop).SessionId
$nonce     = (Get-ItemProperty HKCU:\Software\PassKee -Name HandshakeNonce).HandshakeNonce
dotnet run --project src/PassKee.Harness -c Release -- `
    --pipe "PassKee.$sessionId" `
    --nonce $nonce `
    --rp webauthn.io `
    --smoke
```

Expected output (exit code 0):

```
[Harness] Pipe: PassKee.1
[Harness] Connecting to plugin pipe... OK
[Harness] Handshake complete.
[Harness] No CDP client — running pipe-only (smoke mode).
[Smoke] createPasskey... OK (AbCdEf123456...)
[Smoke] listCredentials... OK (1 credential(s))
[Smoke] signAssertion... OK
[Smoke] deleteCredential... OK
[Smoke] All checks PASSED.
```

> As of Phase 2.1, `--smoke` mode is pipe-only: `PasskeeHarness.StartAsync`
> skips CDP when the client is null, and `RunSmokeTestAsync` never touches the
> browser. Chrome is only needed for the interactive/browser flow in Step 6.

---

## Step 6 — Browser scenario (webauthn.io)

1. Launch Chrome with remote debugging enabled:

```powershell
Start-Process chrome "--remote-debugging-port=9222 --no-first-run --no-default-browser-check"
```

2. Run the harness in interactive mode (pipe + CDP):

```powershell
$sessionId = (Get-Process KeePass).SessionId
$nonce     = (Get-ItemProperty HKCU:\Software\PassKee -Name HandshakeNonce).HandshakeNonce
dotnet run --project src/PassKee.Harness -c Release -- `
    --nonce $nonce --rp webauthn.io
```

3. After `Virtual authenticator installed. Ready.` is printed, navigate Chrome
   to <https://webauthn.io>.

4. Register a passkey:
   - Enter a username (e.g. `passkee-test-<timestamp>`).
   - Click **Register**. Chrome's virtual authenticator handles the
     `navigator.credentials.create()` call via the CDP harness.
   - In the harness terminal type `create` then press Enter.
   - Expected: `Created: <credentialId>` printed.

5. Verify the entry in KeePass:
   - In KeePass, look for a **Passkeys** group under the root.
   - It should contain one entry titled `webauthn.io / <userName>`.

6. Login with the passkey:
   - On webauthn.io click **Authenticate**.
   - In the harness terminal type `sign <credentialId>` then press Enter.
   - Expected: `Signature OK`.

7. Teardown:
   - Type `quit` in the harness to disconnect.
   - In KeePass, select the entry in the Passkeys group and press Delete.
   - Run `list webauthn.io` in a new harness session to confirm empty.

---

## Step 7 — Verify teardown

```powershell
# Nonce should be cleared after the first successful handshake.
$nonce = (Get-ItemProperty HKCU:\Software\PassKee -ErrorAction SilentlyContinue).HandshakeNonce
if ($null -eq $nonce) { Write-Host "Nonce cleared — OK" } else { Write-Warning "Nonce still present" }
```

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| PassKee menu missing from Tools | Plugin DLL not copied / wrong path | Re-run `build-plugin.ps1`; check KeePass log (`View → Show Log`) |
| `BadImageFormatException` in KeePass log | Architecture mismatch | Check KeePass bitness; PassKee.dll is AnyCPU and should adapt automatically |
| `[Harness] ERROR connecting to plugin` / timeout | KeePass not running, no `.kdbx` open, or plugin failed to start | Open a `.kdbx` in KeePass; check Tools → PassKee → OS compatibility |
| `Pipe busy` / `another instance is active` | Second KeePass process holds the pipe | Close the duplicate KeePass window |
| `client_unauthorized` | Handshake nonce expired (5 min TTL) or already consumed | Restart KeePass to regenerate nonce; read it again from registry |
| `vault_locked` | No `.kdbx` open in KeePass | Open a database in KeePass before running the harness |
| webauthn.io rejects attestation | RP policy blocks `none` attestation or zero AAGUID | Expected for enterprise RPs with strict attestation policies; webauthn.io should accept none attestation |
| `playwright install` fails | Playwright CLI not installed globally | `dotnet tool install --global Microsoft.Playwright.CLI` first |
| Chrome CDP connection refused | Chrome not started with `--remote-debugging-port=9222` | Re-launch Chrome with the flag; confirm with `Invoke-WebRequest http://localhost:9222/json` |

---

## Phase 2.1 — MSIX install runbook

Phase 2.1 takes the Rust provider from "DLL compiles" to "MSIX installs cleanly
on Win11 24H2". Scope explicitly stops at `Add-AppxPackage` success —
`WebAuthNPluginAddAuthenticator` + Settings visibility + live COM activation
are Phase 2.2.

### Prerequisites (Phase 2.1-specific)

| Requirement | Notes |
|---|---|
| Rust Windows DLL + EXE | `passkee_provider.dll` + `passkee-provider.exe` built for `x86_64-pc-windows-msvc`. Build on Windows (`cargo build --target x86_64-pc-windows-msvc --release`) or on WSL2 (`cargo xwin build …`). If you build on WSL, point the validator at the WSL UNC path — see below. |
| Windows SDK | For `makeappx.exe` and `signtool.exe` (installed with Visual Studio Build Tools or standalone Win10/11 SDK) |
| Admin PowerShell | Required **once** to install the dev cert into `Cert:\LocalMachine\TrustedPeople` |

### Unattended runbook

```powershell
# Default — Rust artifacts expected in the repo-local release dir:
.\scripts\validate-phase2.ps1

# WSL cross-compile pattern — build on WSL, validate on Windows:
.\scripts\validate-phase2.ps1 -RustArtifactDir '\\wsl.localhost\<your-distro>\<path-to-your-checkout>\src\PassKee.Provider\target\x86_64-pc-windows-msvc\release'
```

The WSL path form works because `build-msix.ps1` copies the DLL + EXE into its
own temp staging dir before invoking `makeappx` — `\\wsl.localhost\…` is just
a regular UNC source path to `Copy-Item`. The actual pack runs entirely on
Windows-local paths.

The orchestrator runs 5 steps: ensure-dev-cert → winver diag → build-msix →
sign-msix → install-msix. It prompts once for a PFX password (`SecureString`)
and propagates it to the cert + signing scripts. Pass `-DryRun` for pre-flight
only.

### Expected PASS criteria

- `Get-AppxPackage -Name PassKee.Provider` returns a package with:
  - `Publisher = CN=Marco Lodini, O=PassKee, C=IT` (exact)
  - `Version = 0.0.1.0`
  - `PackageFamilyName` logged by `install-msix.ps1` — **save this**, Phase 2.2 needs it.

### Rollback

```powershell
# Remove the installed package
Remove-AppxPackage -Package (Get-AppxPackage -Name PassKee.Provider).PackageFullName

# Remove the dev cert (thumbprint recorded in out\cert-thumbprint.txt)
$tp = Get-Content .\out\cert-thumbprint.txt
Remove-Item "Cert:\CurrentUser\My\$tp"
Remove-Item "Cert:\LocalMachine\TrustedPeople\$tp"
```

### Known deferred (Phase 2.2)

> **Architecture pivot, Session 3:** the manifest registers `passkee-provider.exe`
> as an out-of-process (`com:ExeServer`) COM server, matching the Microsoft
> PasskeyManager reference sample. In-process DLL activation was our original
> plan but is blocked at runtime by `%ProgramFiles%\WindowsApps\…` ACLs. Phase 2.2
> moves the COM class factory from the DLL (`src/com/dll.rs`) into the EXE's
> `main()` and wires `-PluginActivated` argument handling.

- **EXE-side COM class factory + `-PluginActivated` handler** must be written.
  Until that lands, `CoCreateInstance` on our CLSID will spawn the EXE but
  the EXE won't register its class factory — activation will time out.
- **`WebAuthNPluginAddAuthenticator`** has no call site yet — the MSIX
  installs cleanly but PassKee will **not** appear in Settings → Accounts →
  Passkeys → Advanced options until that API is wired.
- **Runtime vtable validation** via debug-attach (now against the EXE, not
  the DLL).

---

## What this validates

- ECDsa P-256 key generation and PKCS#8 storage in KeePass.
- CTAP2-canonical CBOR encoding of `authData` and `COSE_Key`.
- `authenticatorData` layout (rpIdHash + flags + signCount + AAGUID + credId + COSE_Key).
- IEEE P1363 → DER signature conversion.
- JSON-RPC 2.0 framing over named pipe.
- HKCU nonce handshake.
- PwEntry ↔ `PasskeyRecord` round-trip in the "Passkeys" group.
- **Phase 2.1:** MSIX packaging, self-signed code signing, sideload install
  (after running `validate-phase2.ps1`).

It does **not** yet validate:
- Windows Plug-in Authenticator **activation** (`WebAuthNPluginAddAuthenticator`, Phase 2.2).
- Settings → Passkeys visibility.
- Live COM activation of the DLL by the WebAuthn host.
- RS256 algorithm support.
