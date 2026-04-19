#Requires -Version 5.1
<#
.SYNOPSIS
    Runs the KeePassKeyWin Phase 0.5 smoke test against a running KeePass instance.

.DESCRIPTION
    Automatically discovers the KeePass session ID and HKCU handshake nonce,
    then invokes the harness in --smoke mode (createPasskey -> listCredentials
    -> signAssertion -> deleteCredential). Exits 0 on success, 1 on failure.

.PARAMETER RpId
    Relying-party ID to use for the smoke test. Default: webauthn.io

.PARAMETER Configuration
    Harness build configuration to run. Default: Release

.PARAMETER Nonce
    Override the nonce (skip registry lookup). Useful if you copied the nonce
    from KeePass startup logs.

.EXAMPLE
    .\scripts\smoke-test.ps1
    .\scripts\smoke-test.ps1 -RpId example.com
#>
[CmdletBinding()]
param(
    [string] $RpId          = "webauthn.io",
    [ValidateSet("Debug","Release")]
    [string] $Configuration = "Release",
    [string] $Nonce         = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot

# --- Find KeePass process ---
$keepass = Get-Process -Name "KeePass" -ErrorAction SilentlyContinue |
           Select-Object -First 1
if ($null -eq $keepass) {
    throw "KeePass is not running. Start KeePass and open a .kdbx database, then re-run this script."
}
$sessionId = $keepass.SessionId
Write-Host "[smoke-test] KeePass PID $($keepass.Id), session $sessionId"

# --- Read nonce from registry ---
if ([string]::IsNullOrEmpty($Nonce)) {
    $regValue = $null
    try {
        $regValue = (Get-ItemProperty -Path "HKCU:\Software\KeePassKeyWin" -Name "HandshakeNonce" -ErrorAction Stop).HandshakeNonce
    } catch {
        throw "Handshake nonce not found in HKCU:\Software\KeePassKeyWin\HandshakeNonce. " +
              "Is the KeePassKeyWin plugin loaded and a .kdbx open in KeePass?"
    }
    if ([string]::IsNullOrWhiteSpace($regValue)) {
        throw "HandshakeNonce registry value is empty. Restart KeePass to regenerate it."
    }
    $Nonce = $regValue
    Write-Host "[smoke-test] Nonce: $($Nonce.Substring(0, [Math]::Min(8, $Nonce.Length)))..."
}

# --- Locate harness ---
$harnessProj = Join-Path $repoRoot "src\KeePassKeyWin.Harness\KeePassKeyWin.Harness.csproj"
if (-not (Test-Path $harnessProj)) {
    throw "Harness project not found at '$harnessProj'. Run from the repo root scripts\ directory."
}

# --- Build harness ---
Write-Host "[smoke-test] Building harness ($Configuration)..."
& dotnet build $harnessProj -c $Configuration --nologo
if ($LASTEXITCODE -ne 0) { throw "Harness build failed." }

# --- Run smoke test ---
# Chrome is not required: --smoke mode uses the plugin pipe directly.
Write-Host "[smoke-test] Launching harness in --smoke mode..."
& dotnet run --project $harnessProj -c $Configuration --no-build -- `
    --nonce $Nonce `
    --rp    $RpId  `
    --smoke

$exitCode = $LASTEXITCODE
if ($exitCode -eq 0) {
    Write-Host ""
    Write-Host "[smoke-test] PASSED (exit 0)" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Error "[smoke-test] FAILED (exit $exitCode)"
}
exit $exitCode
