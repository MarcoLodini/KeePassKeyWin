#Requires -Version 5.1
<#
.SYNOPSIS
    Install PassKee.Provider.msix and verify the resulting AppX package registration.

.DESCRIPTION
    Purpose     : Sideload the signed MSIX package via Add-AppxPackage, then
                  verify that Get-AppxPackage finds it with the correct Publisher,
                  Version, and a non-empty PackageFamilyName.
    Prerequisites: The MSIX must already be signed (sign-msix.ps1).
                  The signing cert's public key must be in Cert:\LocalMachine\TrustedPeople
                  (ensure-dev-cert.ps1 installs it there).
    Inputs      : -MsixPath (default: out\PassKee.Provider.msix)
    Outputs     : Console output confirming PackageFamilyName (needed for Phase 2.2)
    Exit codes  : 0 = PASS, 1 = FAIL

    Rollback: Remove-AppxPackage (Get-AppxPackage -Name 'PassKee.Provider').PackageFullName
#>
[CmdletBinding()]
param(
    [string] $MsixPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Resolve paths relative to repo root (script lives in scripts\)
# ---------------------------------------------------------------------------
$repoRoot = Split-Path -Parent $PSScriptRoot

if ([string]::IsNullOrEmpty($MsixPath)) {
    $MsixPath = Join-Path $repoRoot 'out\PassKee.Provider.msix'
} elseif (-not [System.IO.Path]::IsPathRooted($MsixPath)) {
    $MsixPath = Join-Path $repoRoot $MsixPath
}

$expectedPublisher = 'CN=Marco Lodini, O=PassKee, C=IT'
$expectedVersion   = '0.0.1.0'
$packageName       = 'PassKee.Provider'

# ---------------------------------------------------------------------------
# Step 1/3 — Assert MSIX exists
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host '[install-msix] --- Step 1/3: Assert MSIX exists ---'

if (-not (Test-Path $MsixPath)) {
    Write-Host "[install-msix] FAIL: MSIX not found: $MsixPath" -ForegroundColor Red
    Write-Host "[install-msix]   Run build-msix.ps1 then sign-msix.ps1 first."
    exit 1
}
$msixSize = (Get-Item $MsixPath).Length
Write-Host "[install-msix] MSIX: $MsixPath ($msixSize bytes)"

# ---------------------------------------------------------------------------
# Step 2/3 — Install
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host '[install-msix] --- Step 2/3: Add-AppxPackage ---'

# Remove any previously installed version first. If the package isn't installed
# this is a no-op; if it is installed, Update semantics require a higher version
# number — easier to deregister and re-register on the same 0.0.1.0 dev cycle.
$existing = Get-AppxPackage -Name $packageName -ErrorAction SilentlyContinue
if ($null -ne $existing) {
    Write-Host "[install-msix] Removing existing package: $($existing.PackageFullName)"
    try {
        Remove-AppxPackage -Package $existing.PackageFullName
    } catch {
        Write-Host "[install-msix] FAIL: Remove-AppxPackage failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "[install-msix]   Try manually: Remove-AppxPackage -Package '$($existing.PackageFullName)'" -ForegroundColor Yellow
        exit 1
    }
    if ($null -ne (Get-AppxPackage -Name $packageName -ErrorAction SilentlyContinue)) {
        Write-Host "[install-msix] FAIL: Package still registered after Remove-AppxPackage." -ForegroundColor Red
        exit 1
    }
    Write-Host "[install-msix] Existing package removed."
}

try {
    Add-AppxPackage -Path $MsixPath
} catch {
    Write-Host "[install-msix] FAIL: Add-AppxPackage threw an exception:" -ForegroundColor Red
    Write-Host "  $($_.Exception.Message)" -ForegroundColor Red

    # Surface the inner ActivityId / error code if available — MSIX failures
    # often carry a hex error code (e.g. 0x800B0109 = cert not trusted) that
    # is more actionable than the outer message.
    if ($_.Exception.InnerException) {
        Write-Host "  Inner: $($_.Exception.InnerException.Message)" -ForegroundColor Red
    }
    Write-Host ''
    Write-Host "[install-msix] Common causes:" -ForegroundColor Yellow
    Write-Host "  0x800B0109 — cert not trusted. Run ensure-dev-cert.ps1 from an elevated shell." -ForegroundColor Yellow
    Write-Host "  0x80080205 — Publisher in manifest doesn't match signing cert Subject." -ForegroundColor Yellow
    Write-Host "  0x80073CF0 — package already installed at same or higher version; script should have removed it — check Get-AppxPackage manually." -ForegroundColor Yellow
    exit 1
}

Write-Host "[install-msix] Add-AppxPackage completed."

# ---------------------------------------------------------------------------
# Step 3/3 — Verify
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host '[install-msix] --- Step 3/3: Verify package registration ---'

$pkg = Get-AppxPackage -Name $packageName -ErrorAction SilentlyContinue
if ($null -eq $pkg) {
    Write-Host "[install-msix] FAIL: Get-AppxPackage -Name '$packageName' returned nothing." -ForegroundColor Red
    Write-Host "[install-msix]   The package name in the manifest Identity/@Name must be '$packageName'."
    exit 1
}

Write-Host "[install-msix] Package found: $($pkg.PackageFullName)"

# Assert Publisher
if ($pkg.Publisher -cne $expectedPublisher) {
    Write-Host "[install-msix] FAIL: Publisher mismatch." -ForegroundColor Red
    Write-Host "[install-msix]   Expected : '$expectedPublisher'"
    Write-Host "[install-msix]   Got      : '$($pkg.Publisher)'"
    exit 1
}
Write-Host "[install-msix] Publisher: OK ('$($pkg.Publisher)')"

# Assert Version
# $pkg.Version may be a PackageVersion struct (with .Major/.Minor/.Build/.Revision)
# or a plain string ('0.0.1.0') depending on the Appx cmdlet version. ToString()
# gives the dotted-decimal form in both cases, so we compare on that.
$pkgVersionStr = $pkg.Version.ToString()
if ($pkgVersionStr -ne $expectedVersion) {
    Write-Host "[install-msix] FAIL: Version mismatch." -ForegroundColor Red
    Write-Host "[install-msix]   Expected : $expectedVersion"
    Write-Host "[install-msix]   Got      : $pkgVersionStr"
    exit 1
}
Write-Host "[install-msix] Version: OK ($pkgVersionStr)"

# Assert PackageFamilyName non-empty
if ([string]::IsNullOrWhiteSpace($pkg.PackageFamilyName)) {
    Write-Host "[install-msix] FAIL: PackageFamilyName is empty." -ForegroundColor Red
    exit 1
}

# Log PackageFamilyName prominently — Phase 2.2 (WebAuthNPluginAddAuthenticator)
# needs this value to construct the COM activation identity.
Write-Host ''
Write-Host "=========================================================" -ForegroundColor Cyan
Write-Host "  PackageFamilyName : $($pkg.PackageFamilyName)" -ForegroundColor Cyan
Write-Host "  (save this for Phase 2.2 — WebAuthNPluginAddAuthenticator)" -ForegroundColor Cyan
Write-Host "=========================================================" -ForegroundColor Cyan
Write-Host ''

Write-Host "[install-msix] PASS Publisher='$($pkg.Publisher)' Version=$pkgVersionStr PFN=$($pkg.PackageFamilyName)" -ForegroundColor Green
exit 0
