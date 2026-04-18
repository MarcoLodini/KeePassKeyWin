#Requires -Version 5.1
<#
.SYNOPSIS
    Sign PassKee.Provider.msix with a PFX certificate using signtool.

.DESCRIPTION
    Purpose     : Verify that the PFX Subject exactly matches the manifest Publisher
                  (byte-for-byte), then sign the MSIX package with signtool.
    Prerequisites: out\PassKee.Dev.pfx (produced by ensure-dev-cert.ps1)
                  out\PassKee.Provider.msix (produced by build-msix.ps1)
                  Windows SDK signtool.exe reachable via PATH or Windows Kits.
    Inputs      : -PfxPath     (default: out\PassKee.Dev.pfx)
                  -PfxPassword (SecureString; prompted if absent)
                  -MsixPath    (default: out\PassKee.Provider.msix)
    Outputs     : out\PassKee.Provider.msix (signed in-place)
    Exit codes  : 0 = PASS, 1 = FAIL

    IMPORTANT — we NEVER use signtool /a (auto-select). On a dev machine with
    multiple code-signing certs /a picks the wrong one silently.
    Reference: https://learn.microsoft.com/windows/msix/package/create-certificate-package-signing

    Risk #2 mitigation: Publisher/Subject mismatch is the most common silent
    failure path for Add-AppxPackage. This script hard-fails with a diagnostic
    message if they diverge, before signtool is even called.
#>
[CmdletBinding()]
param(
    [string]       $PfxPath     = '',
    [SecureString] $PfxPassword = $null,
    [string]       $MsixPath    = ''
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

if ([string]::IsNullOrEmpty($MsixPath)) {
    $MsixPath = Join-Path $repoRoot 'out\PassKee.Provider.msix'
} elseif (-not [System.IO.Path]::IsPathRooted($MsixPath)) {
    $MsixPath = Join-Path $repoRoot $MsixPath
}

# Manifest lives alongside the appx assets.
$manifestPath = Join-Path $repoRoot 'src\PassKee.Provider\appx\Package.appxmanifest'

# ---------------------------------------------------------------------------
# Prompt for password if not supplied
# ---------------------------------------------------------------------------
if ($null -eq $PfxPassword) {
    Write-Host "[sign-msix] PFX password not provided — prompting."
    $PfxPassword = Read-Host -Prompt 'Enter PFX password' -AsSecureString
}

# ---------------------------------------------------------------------------
# Step 1/4 — Assert inputs exist
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host '[sign-msix] --- Step 1/4: Assert inputs ---'

foreach ($f in @($PfxPath, $MsixPath, $manifestPath)) {
    if (-not (Test-Path $f)) {
        Write-Host "[sign-msix] FAIL: Required file not found: $f" -ForegroundColor Red
        exit 1
    }
    Write-Host "[sign-msix] Found: $f"
}

# ---------------------------------------------------------------------------
# Step 2/4 — Publisher / Subject pre-check (Risk #2 mitigation — CRITICAL)
# ---------------------------------------------------------------------------
#
# The Publisher attribute in Identity/@Publisher MUST be byte-for-byte equal
# to the signing certificate's Subject DN. Windows validates this during
# Add-AppxPackage and returns a confusing 0x80080205 error (or similar) if
# they diverge — with no indication of which string differs.
# We catch the mismatch here, before signing, so the error message is useful.
# Reference: https://learn.microsoft.com/windows/msix/package/create-certificate-package-signing
#
Write-Host ''
Write-Host '[sign-msix] --- Step 2/4: Verify Publisher / Subject match ---'

# Extract Publisher from manifest. The attribute is on the <Identity> element.
$manifestXml = [xml](Get-Content $manifestPath -Raw -Encoding UTF8)
$manifestNs  = 'http://schemas.microsoft.com/appx/manifest/foundation/windows10'
$identityNode = $manifestXml.SelectSingleNode(
    '//*[local-name()="Identity"]'
)
if ($null -eq $identityNode) {
    Write-Host "[sign-msix] FAIL: <Identity> element not found in manifest." -ForegroundColor Red
    exit 1
}
$manifestPublisher = $identityNode.GetAttribute('Publisher')
Write-Host "[sign-msix] Manifest Publisher : '$manifestPublisher'"

# Load the PFX certificate (without importing it into any store).
$pfxCert = $null
try {
    $pfxCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
        $PfxPath,
        $PfxPassword
    )
} catch {
    Write-Host "[sign-msix] FAIL: Could not load PFX from '$PfxPath': $_" -ForegroundColor Red
    exit 1
}
$certSubject = $pfxCert.Subject
Write-Host "[sign-msix] PFX cert Subject   : '$certSubject'"

# Case-sensitive exact match — the CN= format is case-sensitive by convention
# and Windows performs a byte-level comparison during package verification.
if ($certSubject -cne $manifestPublisher) {
    Write-Host '' -ForegroundColor Red
    Write-Host "[sign-msix] FAIL Publisher/Subject mismatch." -ForegroundColor Red
    Write-Host "[sign-msix]   Manifest Publisher : '$manifestPublisher'" -ForegroundColor Red
    Write-Host "[sign-msix]   Cert Subject       : '$certSubject'" -ForegroundColor Red
    Write-Host "[sign-msix]   Fix: update Identity/@Publisher in Package.appxmanifest to match" -ForegroundColor Yellow
    Write-Host "[sign-msix]        the cert Subject, or regenerate the cert with -Subject matching" -ForegroundColor Yellow
    Write-Host "[sign-msix]        the manifest Publisher exactly." -ForegroundColor Yellow
    exit 1
}
Write-Host "[sign-msix] Publisher/Subject match: OK" -ForegroundColor Green

# ---------------------------------------------------------------------------
# Step 3/4 — Locate signtool.exe
# ---------------------------------------------------------------------------
#
# Prefer signtool already on PATH; otherwise glob Windows Kits.
# We never use /a (auto-select) — always sign by explicit /f <pfx>.
# Reference: https://learn.microsoft.com/windows/msix/package/create-certificate-package-signing
#
Write-Host ''
Write-Host '[sign-msix] --- Step 3/4: Locate signtool.exe ---'

$signtool = $null
try {
    $cmd = Get-Command 'signtool.exe' -ErrorAction Stop
    $signtool = $cmd.Source
    Write-Host "[sign-msix] signtool found on PATH: $signtool"
} catch {
    $wkBase = 'C:\Program Files (x86)\Windows Kits\10\bin'
    if (Test-Path $wkBase) {
        $candidates = @(Get-ChildItem -Path $wkBase -Filter 'signtool.exe' -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '\\x64\\' })
        if ($candidates.Count -gt 0) {
            $signtool = ($candidates | Sort-Object {
                $seg = ($_.DirectoryName -split '\\') | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' } | Select-Object -First 1
                if ($seg) { [version]$seg } else { [version]'0.0.0.0' }
            } -Descending | Select-Object -First 1).FullName
            Write-Host "[sign-msix] signtool found via Windows Kits glob: $signtool"
        }
    }
}

if ($null -eq $signtool -or -not (Test-Path $signtool)) {
    Write-Host "[sign-msix] FAIL: signtool.exe not found." -ForegroundColor Red
    Write-Host "[sign-msix]   Install the Windows SDK (Windows App Certification Kit component)."
    Write-Host "[sign-msix]   Typical path: C:\Program Files (x86)\Windows Kits\10\bin\10.0.*\x64\signtool.exe"
    exit 1
}

# ---------------------------------------------------------------------------
# Step 4/4 — Sign
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host '[sign-msix] --- Step 4/4: Sign MSIX ---'

# Convert SecureString password to plain text for the signtool /p argument.
# signtool requires a plain-text password on the command line; there is no
# alternative flag that accepts a SecureString or a credential object.
$bstr      = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PfxPassword)
$plainPwd  = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)

try {
    # /fd SHA256  — file digest algorithm (required for MSIX; SHA1 is rejected)
    # /f <pfx>   — explicit certificate file (never /a auto-select)
    # /p <pwd>   — PFX password
    # No /t or /tr timestamp — not required for local sideload
    & $signtool sign /fd SHA256 /f $PfxPath /p $plainPwd $MsixPath
    $signtoolExit = $LASTEXITCODE
} finally {
    # Clear the plain-text password from the variable as soon as signtool returns.
    $plainPwd = $null
}

if ($signtoolExit -ne 0) {
    Write-Host "[sign-msix] FAIL: signtool exited with code $signtoolExit" -ForegroundColor Red
    exit 1
}

Write-Host ''
Write-Host '[sign-msix] PASS' -ForegroundColor Green
exit 0
