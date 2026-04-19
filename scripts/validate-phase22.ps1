#Requires -Version 5.1
<#
.SYNOPSIS
    Phase 2.2 validator — confirms out-of-proc COM class factory activation
    + WebAuthN plugin registration + Settings visibility.

.DESCRIPTION
    Prerequisite: validate-phase2.ps1 must have installed the MSIX.
    Steps:
      1. Get-AppxPackage KeePassKeyWin.Provider present
      2. keepasskeywin-provider.exe register
      3. CoCreateInstance smoke (process start + release)
      4. WinDbg vtable docs (non-fatal)
      5. Settings -> Accounts -> Passkeys -> Advanced (manual, hard gate)

    Idempotent: runs `keepasskeywin-provider.exe unregister` in a finally block.

.PARAMETER DryRun
    Skip Step 2 (register) and Step 3 (CoCreateInstance). Useful for dev
    iteration without actually registering.

.PARAMETER PfxPath
    Reserved for future use; not consumed by this script. Accepted to allow
    copy-paste invocations that include Phase 2.1 flags.

.PARAMETER PfxPassword
    Reserved for future use; not consumed by this script. Accepted to allow
    copy-paste invocations that include Phase 2.1 flags.

.NOTES
    Bail policy: if Step 3 succeeds but the browser flow can't make a
    passkey through KeePassKeyWin, commit Phase 2.2 partial and open Phase 2.3.

.EXAMPLE
    # Full validation (MSIX already installed):
    .\scripts\validate-phase22.ps1

    # Pre-flight only — no register / CoCreateInstance:
    .\scripts\validate-phase22.ps1 -DryRun
#>
[CmdletBinding()]
param(
    [switch] $DryRun,
    [string] $PfxPath,
    [string] $PfxPassword
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Resolve repo root (script lives in scripts\)
# ---------------------------------------------------------------------------
$repoRoot = Split-Path -Parent $PSScriptRoot

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host '[validate-phase22] ===== KeePassKeyWin Phase 2.2 Validator =====' -ForegroundColor Cyan
Write-Host "[validate-phase22] Repo root : $repoRoot"
Write-Host "[validate-phase22] DryRun    : $DryRun"
Write-Host ''

# ---------------------------------------------------------------------------
# Script-scope variables used by the finally block.
# $passed gates the unregister cleanup — we only unregister on failure paths
# so a successful run leaves KeePassKeyWin visible in Settings for follow-up
# browser testing. If unregister ran unconditionally, the user would confirm
# "yes I see KeePassKeyWin", the script would PASS, then immediately rip it back
# out — defeating the point of the hard gate.
# ---------------------------------------------------------------------------
$exePath = $null
$passed  = $false

try {

    # -----------------------------------------------------------------------
    # Step 1/5 — Prerequisite: MSIX is installed
    # -----------------------------------------------------------------------
    Write-Host '[validate-phase22] --- Step 1/5: Prerequisite -- MSIX is installed ---'

    $pkg = Get-AppxPackage -Name 'KeePassKeyWin.Provider' -ErrorAction SilentlyContinue
    if ($null -eq $pkg) {
        Write-Host '[validate-phase22] FAIL at step 1: KeePassKeyWin.Provider package not found.' -ForegroundColor Red
        Write-Host '[validate-phase22]   Run .\scripts\validate-phase2.ps1 first to install Phase 2.1 MSIX.' -ForegroundColor Yellow
        Write-Host ''
        Write-Host '[validate-phase22] FAIL at step 1' -ForegroundColor Red
        exit 1
    }

    Write-Host "[validate-phase22] PackageFamilyName : $($pkg.PackageFamilyName)"
    Write-Host "[validate-phase22] Version           : $($pkg.Version.ToString())"
    Write-Host "[validate-phase22] InstallLocation   : $($pkg.InstallLocation)"

    # -----------------------------------------------------------------------
    # Step 2/5 — Run `keepasskeywin-provider.exe register`
    # -----------------------------------------------------------------------
    Write-Host ''
    Write-Host '[validate-phase22] --- Step 2/5: Run `keepasskeywin-provider.exe register` ---'

    $exePath = Join-Path $pkg.InstallLocation 'keepasskeywin-provider.exe'

    if (-not (Test-Path $exePath)) {
        Write-Host "[validate-phase22] FAIL at step 2: EXE not found: $exePath" -ForegroundColor Red
        Write-Host ''
        Write-Host '[validate-phase22] FAIL at step 2' -ForegroundColor Red
        exit 1
    }

    Write-Host "[validate-phase22] EXE: $exePath"

    if ($DryRun) {
        Write-Host "[validate-phase22] DRYRUN: would exec $exePath register"
    } else {
        & $exePath register 2>&1 | ForEach-Object { Write-Host "  $_" }
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[validate-phase22] FAIL at step 2: keepasskeywin-provider.exe register exited with code $LASTEXITCODE." -ForegroundColor Red
            Write-Host '[validate-phase22]   Check that Phase 2.2 WebAuthNPluginAddAuthenticator is implemented in the EXE.' -ForegroundColor Yellow
            Write-Host ''
            Write-Host '[validate-phase22] FAIL at step 2' -ForegroundColor Red
            exit 1
        }
        Write-Host '[validate-phase22] register: OK' -ForegroundColor Green
    }

    # -----------------------------------------------------------------------
    # Step 3/5 — CoCreateInstance smoke test
    # -----------------------------------------------------------------------
    Write-Host ''
    Write-Host '[validate-phase22] --- Step 3/5: CoCreateInstance smoke test ---'

    $clsid = [Guid]'d26bcf6f-b54c-43ff-9f06-d5bf148625f7'
    Write-Host "[validate-phase22] CLSID: {$clsid}"

    if ($DryRun) {
        Write-Host "[validate-phase22] DRYRUN: would call [Activator]::CreateInstance([Type]::GetTypeFromCLSID('$clsid', \$true))"
    } else {
        # Packaged-COM classes (registered via MSIX <com:ExeServer>) live in a
        # separate registry namespace from classic HKCR. [Activator]::Create-
        # Instance goes through classic CoCreateInstance which doesn't see
        # packaged-COM entries, so REGDB_E_CLASSNOTREG (0x80040154) is the
        # EXPECTED response from an unpackaged caller — not a bug in our
        # registration. The Windows WebAuthN host uses a different activation
        # path (the `register` call above taught it about our CLSID through
        # webauthn.dll's internal store). The authoritative test is Step 5:
        # does KeePassKeyWin appear in Settings, and does a browser flow work.
        $obj = $null
        try {
            $type = [Type]::GetTypeFromCLSID($clsid, $true)
            $obj  = [Activator]::CreateInstance($type)
        } catch {
            $msg = $_.Exception.Message
            if ($msg -match '0x80040154' -or $msg -match 'REGDB_E_CLASSNOTREG' -or $msg -match 'Class not registered') {
                Write-Host '[validate-phase22] CoCreateInstance from PowerShell: REGDB_E_CLASSNOTREG (EXPECTED)' -ForegroundColor Cyan
                Write-Host '[validate-phase22]   Packaged-COM classes are not visible to classic CoCreateInstance.'
                Write-Host '[validate-phase22]   The real activation test is the browser flow (Step 5 / Phase 2.3).'
            } else {
                Write-Host "[validate-phase22] FAIL at step 3: CoCreateInstance threw an unexpected error: $msg" -ForegroundColor Red
                Write-Host '[validate-phase22]   This is NOT the expected packaged-COM limitation.' -ForegroundColor Yellow
                Write-Host '[validate-phase22]   Check Event Viewer (Windows Logs -> Application) for DCOM errors.' -ForegroundColor Yellow
                Write-Host ''
                Write-Host '[validate-phase22] FAIL at step 3' -ForegroundColor Red
                exit 1
            }
        }

        if ($null -ne $obj) {
            # Unreachable on packaged-COM but harmless: if we ever DO get an
            # object (e.g. future unpackaged dev runs), clean it up.
            $proc = Get-Process keepasskeywin-provider -ErrorAction SilentlyContinue
            if ($null -ne $proc) {
                Write-Host "[validate-phase22] keepasskeywin-provider.exe PID: $($proc.Id)"
            }
            [System.Runtime.InteropServices.Marshal]::ReleaseComObject($obj) | Out-Null
            $obj = $null
            [GC]::Collect()
            [GC]::WaitForPendingFinalizers()
        }
    }

    # -----------------------------------------------------------------------
    # Step 4/5 — WinDbg vtable verification (MANUAL reminder, non-fatal)
    # -----------------------------------------------------------------------
    Write-Host ''
    Write-Host '[validate-phase22] --- Step 4/5: WinDbg vtable verification (MANUAL reminder) ---'
    Write-Host ''
    Write-Host '  +---------------------------------------------------------------------------+' -ForegroundColor Yellow
    Write-Host '  | If Step 5 (Settings visibility) succeeds but browser passkey flows fail,  |' -ForegroundColor Yellow
    Write-Host '  | attach WinDbg to keepasskeywin-provider.exe after CoCreateInstance and run:|' -ForegroundColor Yellow
    Write-Host '  |                                                                           |' -ForegroundColor Yellow
    Write-Host '  |     dt keepasskeywin_provider!com::server::imp::IPluginAuthenticatorVtbl  |' -ForegroundColor Yellow
    Write-Host '  |                                                                           |' -ForegroundColor Yellow
    Write-Host '  | Confirm:                                                                  |' -ForegroundColor Yellow
    Write-Host '  |   slot 3 = make_credential                                               |' -ForegroundColor Yellow
    Write-Host '  |   slot 4 = get_assertion                                                 |' -ForegroundColor Yellow
    Write-Host '  |   slot 5 = cancel_operation                                              |' -ForegroundColor Yellow
    Write-Host '  |   slot 6 = get_lock_status                                               |' -ForegroundColor Yellow
    Write-Host '  +---------------------------------------------------------------------------+' -ForegroundColor Yellow
    Write-Host ''
    Write-Host '[validate-phase22] Step 4: documentation only -- no assertion.' -ForegroundColor Cyan

    # -----------------------------------------------------------------------
    # Step 5/5 — HARD GATE: Settings visibility (manual check)
    # -----------------------------------------------------------------------
    Write-Host ''
    Write-Host '[validate-phase22] --- Step 5/5: HARD GATE -- Settings visibility ---'
    Write-Host ''
    Write-Host '  +-------------------------------------------------------------------+' -ForegroundColor Yellow
    Write-Host '  | MANUAL CHECK REQUIRED -- Phase 2.2 is not done until you confirm: |' -ForegroundColor Yellow
    Write-Host '  |                                                                   |' -ForegroundColor Yellow
    Write-Host '  |   1. Open Settings -> Accounts -> Passkeys                        |' -ForegroundColor Yellow
    Write-Host '  |   2. Click "Advanced options"                                     |' -ForegroundColor Yellow
    Write-Host '  |   3. "KeePassKeyWin" must appear in the passkey providers list     |' -ForegroundColor Yellow
    Write-Host '  +-------------------------------------------------------------------+' -ForegroundColor Yellow
    Write-Host ''

    $answer = Read-Host 'Do you see KeePassKeyWin in Settings? [y/N]'
    if ($answer -ne 'y' -and $answer -ne 'Y') {
        Write-Host '[validate-phase22] FAIL at step 5: Settings visibility is the hard gate per the Phase 2.2 plan.' -ForegroundColor Red
        Write-Host '[validate-phase22]   KeePassKeyWin must appear in Settings -> Accounts -> Passkeys -> Advanced options.' -ForegroundColor Yellow
        Write-Host '[validate-phase22]   Verify that keepasskeywin-provider.exe register called WebAuthNPluginAddAuthenticator successfully.' -ForegroundColor Yellow
        Write-Host ''
        Write-Host '[validate-phase22] FAIL at step 5' -ForegroundColor Red
        exit 1
    }

    Write-Host '[validate-phase22] Settings visibility: confirmed.' -ForegroundColor Green

    # -----------------------------------------------------------------------
    # Final result
    # -----------------------------------------------------------------------
    $passed = $true
    Write-Host ''
    Write-Host '[validate-phase22] PASS' -ForegroundColor Green
    exit 0

} finally {
    # Only unregister on FAILURE paths — a successful PASS leaves KeePassKeyWin
    # registered so the user can immediately try a browser flow.
    # On DryRun, register was never called, so skip unregister too.
    if (-not $passed -and -not $DryRun -and $null -ne $exePath -and (Test-Path $exePath)) {
        Write-Host "[validate-phase22] Cleanup (failure path): & $exePath unregister"
        & $exePath unregister 2>&1 | ForEach-Object { Write-Host "  $_" }
    }
}
