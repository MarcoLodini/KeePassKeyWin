#Requires -Version 5.1
<#
.SYNOPSIS
    Unattended end-to-end validation of KeePassKeyWin Phase 2.1 (MSIX packaging + sideload).

.DESCRIPTION
    Purpose     : Orchestrate the full Phase 2.1 pipeline:
                    1. Bootstrap the developer code-signing certificate.
                    2. Log Windows build info (diagnostic — Risk #7).
                    3. Build & deploy the .NET plugin DLL (delegates to build-plugin.ps1).
                    4. Build the MSIX package from the Rust provider outputs.
                    5. Sign the MSIX package.
                    6. Install and verify the MSIX package.
    Prerequisites:
                  - cargo xwin build --target x86_64-pc-windows-msvc --release must
                    already have been run (produces keepasskeywin-provider.exe).
                  - .NET SDK installed (for the plugin build in Step 3).
                  - Must be run from an elevated (administrator) PowerShell session so
                    ensure-dev-cert.ps1 can install the cert into LocalMachine\TrustedPeople.
                  - Windows SDK (makeappx.exe + signtool.exe) installed.
    Inputs      : -PfxPassword (SecureString; if omitted, prompted once at Step 1 and
                   reused for Steps 4 and 5 automatically — no repeated prompts).
                  -PfxPath (default: out\KeePassKeyWin.Dev.pfx)
                  -MsixPath (default: out\KeePassKeyWin.Provider.msix)
                  -RustArtifactDir — override location of keepasskeywin-provider.exe. Use the
                   WSL UNC path if cross-compiling from WSL2:
                     '\\wsl.localhost\Ubuntu\home\<you>\...\target\x86_64-pc-windows-msvc\release'
                  -KeePassDir — override KeePass install path used by build-plugin.ps1
                   (default: build-plugin.ps1's own default — typically
                   'C:\Program Files\KeePass Password Safe 2').
                  -PluginConfiguration — Debug or Release (default: Release). Live-
                   validation should use Release: TraceLogger's file route exists
                   precisely because Debug.WriteLine is conditionally compiled out
                   of Release builds, so a Debug-built plugin doesn't reproduce the
                   production logging surface.
                  -SkipPlugin — skip Step 3 (use when iterating on the sidecar only
                   and the deployed plugin DLL is known current).
                  -DryRun — pre-flight only; skips all build/sign/install steps.
    Outputs     : Console output; final PASS or FAIL line; exit code 0/1.
    Exit codes  : 0 = PASS, 1 = FAIL

    Phase 2.2 handshake: on PASS, PackageFamilyName is logged prominently by
    install-msix.ps1 (Step 6/6). Record it for the next session.

    Rollback: Remove-AppxPackage (Get-AppxPackage -Name 'KeePassKeyWin.Provider').PackageFullName

.EXAMPLE
    # Elevated PowerShell — runs the full pipeline (plugin + sidecar), prompts
    # for PFX password once:
    .\scripts\validate-phase2.ps1

    # Supply password up front (CI / automated):
    $pwd = ConvertTo-SecureString 'MyPfxSecret' -AsPlainText -Force
    .\scripts\validate-phase2.ps1 -PfxPassword $pwd

    # Iterate on the sidecar only — skip plugin DLL rebuild:
    .\scripts\validate-phase2.ps1 -SkipPlugin

    # Pre-flight only (no build, sign, or install):
    .\scripts\validate-phase2.ps1 -DryRun
#>
[CmdletBinding()]
param(
    [SecureString] $PfxPassword         = $null,
    [string]       $PfxPath             = '',
    [string]       $MsixPath            = '',
    [string]       $RustArtifactDir     = '',
    [string]       $KeePassDir          = '',
    [ValidateSet('Debug','Release')]
    [string]       $PluginConfiguration = 'Release',
    [switch]       $SkipPlugin,
    [switch]       $DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Resolve repo root (script lives in scripts\)
# ---------------------------------------------------------------------------
$repoRoot  = Split-Path -Parent $PSScriptRoot
$scriptsDir = $PSScriptRoot

if ([string]::IsNullOrEmpty($PfxPath)) {
    $PfxPath = Join-Path $repoRoot 'out\KeePassKeyWin.Dev.pfx'
} elseif (-not [System.IO.Path]::IsPathRooted($PfxPath)) {
    $PfxPath = Join-Path $repoRoot $PfxPath
}

if ([string]::IsNullOrEmpty($MsixPath)) {
    $MsixPath = Join-Path $repoRoot 'out\KeePassKeyWin.Provider.msix'
} elseif (-not [System.IO.Path]::IsPathRooted($MsixPath)) {
    $MsixPath = Join-Path $repoRoot $MsixPath
}

# ---------------------------------------------------------------------------
# Helper — invoke a sub-script and propagate failure
# ---------------------------------------------------------------------------
$Script:currentStep = 0

function Invoke-Step {
    param(
        [int]    $StepNum,
        [int]    $TotalSteps,
        [string] $Label,
        [scriptblock] $Body
    )
    $Script:currentStep = $StepNum
    Write-Host ''
    Write-Host "[validate-phase2] =============================" -ForegroundColor Cyan
    Write-Host "[validate-phase2] Step $StepNum/$TotalSteps — $Label" -ForegroundColor Cyan
    Write-Host "[validate-phase2] =============================" -ForegroundColor Cyan
    try {
        & $Body
    } catch {
        Write-Host ''
        Write-Host "[validate-phase2] FAIL at step $StepNum ($Label): $_" -ForegroundColor Red
        Write-Host ''
        Write-Host "[validate-phase2] FAIL at step $StepNum" -ForegroundColor Red
        exit 1
    }
}

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host "[validate-phase2] ===== KeePassKeyWin Phase 2.1 Validator =====" -ForegroundColor Cyan
Write-Host "[validate-phase2] Repo root            : $repoRoot"
Write-Host "[validate-phase2] PfxPath              : $PfxPath"
Write-Host "[validate-phase2] MsixPath             : $MsixPath"
Write-Host "[validate-phase2] PluginConfiguration  : $PluginConfiguration"
Write-Host "[validate-phase2] SkipPlugin           : $SkipPlugin"
Write-Host "[validate-phase2] DryRun               : $DryRun"
Write-Host ''

# ---------------------------------------------------------------------------
# Pre-flight checks (always run, even in DryRun)
# ---------------------------------------------------------------------------
Write-Host '[validate-phase2] --- Pre-flight checks ---'

# Check that the Rust release outputs exist — without them nothing else works.
if ([string]::IsNullOrEmpty($RustArtifactDir)) {
    $releaseDir = Join-Path $repoRoot 'src\KeePassKeyWin.Provider\target\x86_64-pc-windows-msvc\release'
} else {
    $releaseDir = $RustArtifactDir
}
$providerExe = Join-Path $releaseDir 'keepasskeywin-provider.exe'
$manifestFile = Join-Path $repoRoot 'src\KeePassKeyWin.Provider\appx\Package.appxmanifest'

Write-Host "[validate-phase2] Rust artifact dir: $releaseDir"

$allOk = $true

foreach ($f in @($providerExe, $manifestFile)) {
    $ok = Test-Path $f
    $status = if ($ok) { 'PASS' } else { 'FAIL' }
    $color  = if ($ok) { 'Green' } else { 'Red' }
    Write-Host ("[validate-phase2] {0,-65} [{1}]" -f $f, $status) -ForegroundColor $color
    $allOk = $allOk -and $ok
}

if (-not $allOk) {
    Write-Host ''
    Write-Host '[validate-phase2] FAIL: pre-flight checks — missing Rust build outputs.' -ForegroundColor Red
    Write-Host '[validate-phase2]   On Windows (Rust installed): cargo build --target x86_64-pc-windows-msvc --release' -ForegroundColor Yellow
    Write-Host '[validate-phase2]   On WSL2 (cross-compile):     cargo xwin build --target x86_64-pc-windows-msvc --release' -ForegroundColor Yellow
    Write-Host '[validate-phase2]   If built on WSL2, re-run with:' -ForegroundColor Yellow
    Write-Host "[validate-phase2]     -RustArtifactDir '\\wsl.localhost\<distro>\home\<you>\...\target\x86_64-pc-windows-msvc\release'" -ForegroundColor Yellow
    Write-Host ''
    Write-Host '[validate-phase2] FAIL at step 0'
    exit 1
}

Write-Host '[validate-phase2] Pre-flight: OK' -ForegroundColor Green

if ($DryRun) {
    Write-Host ''
    Write-Host '[validate-phase2] -DryRun specified. Stopping after pre-flight.' -ForegroundColor Cyan
    Write-Host ''
    Write-Host '[validate-phase2] PASS (dry-run)' -ForegroundColor Green
    exit 0
}

# ---------------------------------------------------------------------------
# Prompt for PFX password once — pass it through to sub-scripts so the
# user is not prompted three separate times.
# ---------------------------------------------------------------------------
if ($null -eq $PfxPassword) {
    Write-Host ''
    Write-Host '[validate-phase2] PFX password not provided — prompting (used for cert export + signing).'
    $PfxPassword = Read-Host -Prompt 'Enter PFX password' -AsSecureString
}

# ---------------------------------------------------------------------------
# Step 1/6 — Ensure developer cert
# ---------------------------------------------------------------------------
Invoke-Step 1 6 'Ensure developer certificate' {
    $certScript = Join-Path $scriptsDir 'ensure-dev-cert.ps1'
    & $certScript -PfxPath $PfxPath -PfxPassword $PfxPassword
    if ($LASTEXITCODE -ne 0) {
        throw "ensure-dev-cert.ps1 exited with code $LASTEXITCODE"
    }
}

# ---------------------------------------------------------------------------
# Step 2/6 — Log Windows build info (Risk #7 diagnostic)
# ---------------------------------------------------------------------------
#
# MaxVersionTested="10.0.26100.0" in the manifest may cause a warning on
# newer Cumulative Updates. Logging the actual build here helps correlate
# any future failures with KB update levels.
# Reference: Risk #7 in the Phase 2.1 plan.
#
Invoke-Step 2 6 'Log Windows build info' {
    Write-Host '[validate-phase2] Windows version info (winver diagnostic — Risk #7):'
    try {
        $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
        $displayVersion = $cv.DisplayVersion
        $buildNumber    = $cv.CurrentBuildNumber
        $ubr            = $cv.UBR          # Update Build Revision
        $productName    = $cv.ProductName
        Write-Host "  ProductName    : $productName"
        Write-Host "  DisplayVersion : $displayVersion"
        Write-Host "  BuildNumber    : $buildNumber.$ubr"
        Write-Host "  (ManifestMaxVersionTested: 10.0.26100.0 — if BuildNumber is higher, advisory only)"
    } catch {
        Write-Host "  (could not read version registry: $_)" -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------------------
# Step 3/6 — Build & deploy plugin DLL (delegates to build-plugin.ps1)
# ---------------------------------------------------------------------------
#
# Rationale: validate-phase2 + validate-phase22 historically only rebuilt the
# Rust sidecar via build-msix → install-msix. The .NET plugin DLL had to be
# rebuilt + redeployed with a separate `build-plugin.ps1` invocation, which
# was easy to forget — and a stale plugin DLL paired with a fresh sidecar
# manifests as a runtime contract mismatch (e.g. KEEPASSKEYWIN_LOG_PLUGIN_PII
# gate appears to "work" because the OLD plugin's unconditional logging was
# what produced the PII output). Rolling build-plugin into this script
# means a single invocation rebuilds both halves of the IPC contract.
#
# -SkipPlugin lets the user opt out when iterating purely on sidecar /
# packaging code and the deployed plugin DLL is known current.
#
if ($SkipPlugin) {
    Write-Host ''
    Write-Host "[validate-phase2] Step 3/6 — Build & deploy plugin DLL  [SKIPPED via -SkipPlugin]" -ForegroundColor Yellow
    Write-Host '[validate-phase2] Plugin DLL in KeePass\Plugins\ assumed current — runtime contract mismatch is on you.' -ForegroundColor Yellow
} else {
    Invoke-Step 3 6 'Build & deploy plugin DLL' {
        $pluginScript = Join-Path $scriptsDir 'build-plugin.ps1'
        $pluginArgs   = @('-Configuration', $PluginConfiguration)
        if (-not [string]::IsNullOrEmpty($KeePassDir)) {
            $pluginArgs += @('-KeePassDir', $KeePassDir)
        }
        & $pluginScript @pluginArgs
        if ($LASTEXITCODE -ne 0) {
            throw "build-plugin.ps1 exited with code $LASTEXITCODE"
        }
    }
}

# ---------------------------------------------------------------------------
# Step 4/6 — Build MSIX
# ---------------------------------------------------------------------------
Invoke-Step 4 6 'Build MSIX package' {
    $buildScript = Join-Path $scriptsDir 'build-msix.ps1'
    if ([string]::IsNullOrEmpty($RustArtifactDir)) {
        & $buildScript
    } else {
        & $buildScript -RustArtifactDir $RustArtifactDir
    }
    if ($LASTEXITCODE -ne 0) {
        throw "build-msix.ps1 exited with code $LASTEXITCODE"
    }
}

# ---------------------------------------------------------------------------
# Step 5/6 — Sign MSIX
# ---------------------------------------------------------------------------
Invoke-Step 5 6 'Sign MSIX package' {
    $signScript = Join-Path $scriptsDir 'sign-msix.ps1'
    & $signScript -PfxPath $PfxPath -PfxPassword $PfxPassword -MsixPath $MsixPath
    if ($LASTEXITCODE -ne 0) {
        throw "sign-msix.ps1 exited with code $LASTEXITCODE"
    }
}

# ---------------------------------------------------------------------------
# Step 6/6 — Install and verify
# ---------------------------------------------------------------------------
Invoke-Step 6 6 'Install and verify MSIX' {
    $installScript = Join-Path $scriptsDir 'install-msix.ps1'
    & $installScript -MsixPath $MsixPath
    if ($LASTEXITCODE -ne 0) {
        throw "install-msix.ps1 exited with code $LASTEXITCODE"
    }
}

# ---------------------------------------------------------------------------
# Final result
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host '[validate-phase2] PASS' -ForegroundColor Green
exit 0
