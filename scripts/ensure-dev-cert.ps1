#Requires -Version 5.1
<#
.SYNOPSIS
    Idempotent self-signed developer certificate bootstrap for PassKee MSIX signing.

.DESCRIPTION
    Purpose     : Create and trust a self-signed code-signing certificate so that
                  sign-msix.ps1 can sign PassKee.Provider.msix without a purchased cert.
    Prerequisites: Windows 11; PowerShell 5.1+; the TrustedPeople import step requires
                  an elevated (admin) session.
    Inputs      : -Subject     (default: 'CN=Marco Lodini, O=PassKee, C=IT')
                  -PfxPath     (default: 'out\PassKee.Dev.pfx', relative to repo root)
                  -PfxPassword (SecureString; prompted if absent)
    Outputs     : out\PassKee.Dev.pfx      — the signing credential (gitignored)
                  out\cert-thumbprint.txt  — thumbprint for later cleanup
    Exit codes  : 0 = PASS, 1 = FAIL

    Reference: https://learn.microsoft.com/windows/msix/package/create-certificate-package-signing
#>
[CmdletBinding()]
param(
    [string]       $Subject     = 'CN=Marco Lodini, O=PassKee, C=IT',
    [string]       $PfxPath     = '',
    [SecureString] $PfxPassword = $null
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Resolve paths relative to repo root (script lives in scripts\)
# ---------------------------------------------------------------------------
$repoRoot = Split-Path -Parent $PSScriptRoot

if ([string]::IsNullOrEmpty($PfxPath)) {
    $PfxPath = Join-Path $repoRoot 'out\PassKee.Dev.pfx'
} elseif (-not [System.IO.Path]::IsPathRooted($PfxPath)) {
    $PfxPath = Join-Path $repoRoot $PfxPath
}

$outDir          = Split-Path -Parent $PfxPath
$thumbprintFile  = Join-Path $outDir 'cert-thumbprint.txt'

# ---------------------------------------------------------------------------
# Prompt for password if not supplied
# ---------------------------------------------------------------------------
if ($null -eq $PfxPassword) {
    Write-Host "[ensure-dev-cert] PFX password not provided — prompting."
    $PfxPassword = Read-Host -Prompt 'Enter PFX export password' -AsSecureString
}

# ---------------------------------------------------------------------------
# Step 1/5 — Ensure out\ exists
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host '[ensure-dev-cert] --- Step 1/5: Ensure output directory ---'
if (-not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    Write-Host "[ensure-dev-cert] Created: $outDir"
} else {
    Write-Host "[ensure-dev-cert] Output directory: $outDir (already exists)"
}

# ---------------------------------------------------------------------------
# Step 2/5 — Find or create the signing cert in CurrentUser\My
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host '[ensure-dev-cert] --- Step 2/5: Find or create cert in Cert:\CurrentUser\My ---'

# Search for an existing cert with exact Subject, Code Signing EKU, and not-yet-expired.
# We match Subject with -ceq (case-sensitive) to avoid surprises. An expired cert still
# signs fine, but Add-AppxPackage rejects the resulting MSIX with 0x800B0101 — so we
# treat an expired match as absent and create a fresh one.
$existingCerts = @(
    Get-ChildItem -Path 'Cert:\CurrentUser\My' -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Subject -ceq $Subject -and
        $_.NotAfter -gt (Get-Date) -and
        ($_.EnhancedKeyUsageList | Where-Object { $_.ObjectId -eq '1.3.6.1.5.5.7.3.3' })
    }
)

$cert = $null
if ($existingCerts.Count -gt 0) {
    # Prefer the one with the furthest expiry.
    $cert = $existingCerts | Sort-Object NotAfter -Descending | Select-Object -First 1
    Write-Host "[ensure-dev-cert] Reusing existing cert: Subject='$($cert.Subject)' Thumbprint=$($cert.Thumbprint) Expiry=$($cert.NotAfter.ToString('yyyy-MM-dd'))"
} else {
    Write-Host "[ensure-dev-cert] No matching cert found — creating new one."
    # EKU 1.3.6.1.5.5.7.3.3 = Code Signing
    # 2.5.29.19={text} = BasicConstraints (isCA=false, required for MSIX signing)
    # Reference: https://learn.microsoft.com/windows/msix/package/create-certificate-package-signing
    $cert = New-SelfSignedCertificate `
        -Type           Custom `
        -KeyUsage       DigitalSignature `
        -CertStoreLocation 'Cert:\CurrentUser\My' `
        -TextExtension  @('2.5.29.37={text}1.3.6.1.5.5.7.3.3', '2.5.29.19={text}') `
        -Subject        $Subject `
        -NotAfter       (Get-Date).AddYears(1) `
        -FriendlyName   'PassKee Dev'
    Write-Host "[ensure-dev-cert] Created cert: Thumbprint=$($cert.Thumbprint) Expiry=$($cert.NotAfter.ToString('yyyy-MM-dd'))"
}

# ---------------------------------------------------------------------------
# Step 3/5 — Export .pfx
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host "[ensure-dev-cert] --- Step 3/5: Export PFX -> $PfxPath ---"

Export-PfxCertificate -Cert $cert -FilePath $PfxPath -Password $PfxPassword -Force | Out-Null
if (-not (Test-Path $PfxPath)) {
    Write-Host "[ensure-dev-cert] FAIL: PFX was not written to $PfxPath" -ForegroundColor Red
    exit 1
}
Write-Host "[ensure-dev-cert] PFX exported: $PfxPath"

# Record thumbprint for easy cleanup later (cert is in CurrentUser\My and LocalMachine\TrustedPeople).
Set-Content -Path $thumbprintFile -Value $cert.Thumbprint -Encoding UTF8
Write-Host "[ensure-dev-cert] Thumbprint recorded: $thumbprintFile"
Write-Host "[ensure-dev-cert]   To remove later: Remove-Item 'Cert:\CurrentUser\My\$($cert.Thumbprint)'; Remove-Item 'Cert:\LocalMachine\TrustedPeople\$($cert.Thumbprint)'"

# ---------------------------------------------------------------------------
# Step 4/5 — Install public half into LocalMachine\TrustedPeople
# ---------------------------------------------------------------------------
#
# TrustedPeople is the correct store for MSIX sideload trust — NOT TrustedRoot.
# Without this, Add-AppxPackage returns 0x800B0109 (certificate chain not trusted)
# even if Developer Mode is off.
# Reference: https://learn.microsoft.com/windows/msix/package/sign-msix-package-guide
#
Write-Host ''
Write-Host '[ensure-dev-cert] --- Step 4/5: Install cert into Cert:\LocalMachine\TrustedPeople ---'

# Check for admin — writing to LocalMachine requires elevation.
$isAdmin = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "[ensure-dev-cert] FAIL: Not running as administrator." -ForegroundColor Red
    Write-Host "[ensure-dev-cert]   Re-run this script once from an elevated PowerShell; the cert"
    Write-Host "[ensure-dev-cert]   must be installed into LocalMachine\TrustedPeople for MSIX"
    Write-Host "[ensure-dev-cert]   sideload to work without Developer Mode."
    exit 1
}

$trustedPeopleStore = New-Object System.Security.Cryptography.X509Certificates.X509Store(
    [System.Security.Cryptography.X509Certificates.StoreName]::TrustedPeople,
    [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
)
$trustedPeopleStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
try {
    $alreadyTrusted = $trustedPeopleStore.Certificates | Where-Object { $_.Thumbprint -ceq $cert.Thumbprint }
    if ($alreadyTrusted) {
        Write-Host "[ensure-dev-cert] Cert already present in LocalMachine\TrustedPeople — skipping import."
    } else {
        $trustedPeopleStore.Add($cert)
        Write-Host "[ensure-dev-cert] Cert added to LocalMachine\TrustedPeople: Thumbprint=$($cert.Thumbprint)"
    }
} finally {
    $trustedPeopleStore.Close()
}

# ---------------------------------------------------------------------------
# Step 5/5 — Final verification
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host '[ensure-dev-cert] --- Step 5/5: Verify ---'

$verifyInMy = Get-ChildItem -Path 'Cert:\CurrentUser\My' |
    Where-Object { $_.Thumbprint -ceq $cert.Thumbprint }
$verifyInTrusted = Get-ChildItem -Path 'Cert:\LocalMachine\TrustedPeople' -ErrorAction SilentlyContinue |
    Where-Object { $_.Thumbprint -ceq $cert.Thumbprint }

if ($null -eq $verifyInMy) {
    Write-Host "[ensure-dev-cert] FAIL: Cert not found in CurrentUser\My after create/reuse." -ForegroundColor Red
    exit 1
}
if ($null -eq $verifyInTrusted) {
    Write-Host "[ensure-dev-cert] FAIL: Cert not found in LocalMachine\TrustedPeople after import." -ForegroundColor Red
    exit 1
}

Write-Host "[ensure-dev-cert] CurrentUser\My:            OK ($($cert.Thumbprint))"
Write-Host "[ensure-dev-cert] LocalMachine\TrustedPeople: OK ($($cert.Thumbprint))"
Write-Host "[ensure-dev-cert] PFX file:                   $PfxPath"
Write-Host ''
Write-Host "[ensure-dev-cert] PASS Subject='$Subject' Thumbprint=$($cert.Thumbprint)" -ForegroundColor Green
exit 0
