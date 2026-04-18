#Requires -Version 5.1
<#
.SYNOPSIS
    Stage and pack PassKee.Provider into an MSIX package using makeappx.

.DESCRIPTION
    Purpose     : Assert that the Rust build outputs exist, stage them alongside
                  the MSIX manifest and Assets, then invoke makeappx to produce
                  out\PassKee.Provider.msix.
    Prerequisites: cargo xwin build --target x86_64-pc-windows-msvc --release must
                  have been run beforehand (WSL2 or native-Windows).
                  Windows SDK makeappx.exe must be reachable (via PATH or the
                  standard Windows Kits installation).
    Inputs      : -RustArtifactDir (optional) — source directory for passkee_provider.dll +
                   passkee-provider.exe. Defaults to the repo-local release path. If you
                   build on WSL and validate on Windows, pass the UNC path, e.g.:
                     -RustArtifactDir '\\wsl.localhost\Ubuntu\home\<you>\...\target\x86_64-pc-windows-msvc\release'
    Outputs     : out\PassKee.Provider.msix
    Exit codes  : 0 = PASS, 1 = FAIL

    Reference: https://learn.microsoft.com/windows/msix/package/create-app-package-with-makeappx-tool
#>
[CmdletBinding()]
param(
    [string] $RustArtifactDir = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Resolve repo root (script lives in scripts\)
# ---------------------------------------------------------------------------
$repoRoot = Split-Path -Parent $PSScriptRoot

# ---------------------------------------------------------------------------
# Step 1/5 — Assert Rust build outputs exist
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host '[build-msix] --- Step 1/5: Assert Rust build outputs ---'

if ([string]::IsNullOrEmpty($RustArtifactDir)) {
    $releaseDir = Join-Path $repoRoot 'src\PassKee.Provider\target\x86_64-pc-windows-msvc\release'
} else {
    $releaseDir = $RustArtifactDir
}
$providerDll = Join-Path $releaseDir 'passkee_provider.dll'
$providerExe = Join-Path $releaseDir 'passkee-provider.exe'

Write-Host "[build-msix] Rust artifact dir: $releaseDir"

foreach ($required in @($providerDll, $providerExe)) {
    if (-not (Test-Path $required)) {
        Write-Host "[build-msix] FAIL: Required build output not found: $required" -ForegroundColor Red
        Write-Host "[build-msix]   On Windows with Rust installed: cargo build --target x86_64-pc-windows-msvc --release" -ForegroundColor Yellow
        Write-Host "[build-msix]   On WSL2 (cross-compile):        cargo xwin build --target x86_64-pc-windows-msvc --release" -ForegroundColor Yellow
        Write-Host "[build-msix]   If built on WSL2, run with: -RustArtifactDir '\\wsl.localhost\<distro>\...\target\x86_64-pc-windows-msvc\release'" -ForegroundColor Yellow
        exit 1
    }
    $size = (Get-Item $required).Length
    Write-Host "[build-msix] Found: $([System.IO.Path]::GetFileName($required))  ($size bytes)"
}

# ---------------------------------------------------------------------------
# Step 2/5 — Assert Assets exist
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host '[build-msix] --- Step 2/5: Assert Assets ---'

$assetsDir = Join-Path $repoRoot 'src\PassKee.Provider\appx\Assets'
# Parentheses are required: on PS 6+ `Join-Path` has `-AdditionalChildPath`,
# so a bare `Join-Path a b, c, d` binds the commas to the first call as an
# array argument instead of producing three separate array elements.
$requiredAssets = @(
    (Join-Path $assetsDir 'StoreLogo.png'),
    (Join-Path $assetsDir 'Square150x150Logo.png'),
    (Join-Path $assetsDir 'Square44x44Logo.png')
)

foreach ($asset in $requiredAssets) {
    if (-not (Test-Path $asset)) {
        Write-Host "[build-msix] FAIL: Required asset not found: $asset" -ForegroundColor Red
        Write-Host "[build-msix]   Commit the placeholder PNGs under src\PassKee.Provider\appx\Assets\" -ForegroundColor Yellow
        exit 1
    }
    Write-Host "[build-msix] Found asset: $([System.IO.Path]::GetFileName($asset))"
}

$manifestSrc = Join-Path $repoRoot 'src\PassKee.Provider\appx\Package.appxmanifest'
if (-not (Test-Path $manifestSrc)) {
    Write-Host "[build-msix] FAIL: Manifest not found: $manifestSrc" -ForegroundColor Red
    exit 1
}
Write-Host "[build-msix] Found manifest: Package.appxmanifest"

# ---------------------------------------------------------------------------
# Step 3/5 — Create staging directory (fresh, never reused)
# ---------------------------------------------------------------------------
#
# We always use a brand-new temp dir. Reusing a stale staging dir silently
# bloats the package if old files are left behind from a previous run.
#
Write-Host ''
Write-Host '[build-msix] --- Step 3/5: Create staging directory ---'

$outDir  = Join-Path $repoRoot 'out'
if (-not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    Write-Host "[build-msix] Created: $outDir"
}

$stagingGuid = [System.Guid]::NewGuid().ToString('N')
$stagingDir  = Join-Path ([System.IO.Path]::GetTempPath()) "passkee-msix-staging-$stagingGuid"
New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $stagingDir 'Assets') -Force | Out-Null
Write-Host "[build-msix] Staging directory: $stagingDir"

# ---------------------------------------------------------------------------
# Copy files into staging
# ---------------------------------------------------------------------------
# makeappx expects the manifest to be named AppxManifest.xml inside the content
# directory — Package.appxmanifest is the Visual Studio source-file convention,
# which VS renames during its own packaging. Doing manual `makeappx pack` means
# we rename here. See https://learn.microsoft.com/windows/msix/package/manual-packaging-root
Copy-Item $manifestSrc (Join-Path $stagingDir 'AppxManifest.xml') -Force
Write-Host "[build-msix] Staged: AppxManifest.xml (renamed from Package.appxmanifest)"

Copy-Item $providerDll (Join-Path $stagingDir 'passkee_provider.dll') -Force
Write-Host "[build-msix] Staged: passkee_provider.dll"

Copy-Item $providerExe (Join-Path $stagingDir 'passkee-provider.exe') -Force
Write-Host "[build-msix] Staged: passkee-provider.exe"

foreach ($asset in $requiredAssets) {
    $dest = Join-Path $stagingDir "Assets\$([System.IO.Path]::GetFileName($asset))"
    Copy-Item $asset $dest -Force
    Write-Host "[build-msix] Staged asset: $([System.IO.Path]::GetFileName($asset))"
}

# ---------------------------------------------------------------------------
# Step 4/5 — Locate makeappx.exe
# ---------------------------------------------------------------------------
#
# Prefer makeappx already on PATH; otherwise glob the Windows Kits installation
# and pick the newest SDK version available.
# Reference: https://learn.microsoft.com/windows/msix/package/create-app-package-with-makeappx-tool
#
Write-Host ''
Write-Host '[build-msix] --- Step 4/5: Locate makeappx.exe ---'

$makeappx = $null
try {
    $cmd = Get-Command 'makeappx.exe' -ErrorAction Stop
    $makeappx = $cmd.Source
    Write-Host "[build-msix] makeappx found on PATH: $makeappx"
} catch {
    # Not on PATH — search Windows Kits
    $wkBase = 'C:\Program Files (x86)\Windows Kits\10\bin'
    if (Test-Path $wkBase) {
        $candidates = @(Get-ChildItem -Path $wkBase -Filter 'makeappx.exe' -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '\\x64\\' })
        if ($candidates.Count -gt 0) {
            # Sort by the SDK version folder (e.g. 10.0.22621.0) — pick highest.
            $makeappx = ($candidates | Sort-Object {
                # Extract the version segment from the path for numeric sort.
                $seg = ($_.DirectoryName -split '\\') | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' } | Select-Object -First 1
                if ($seg) { [version]$seg } else { [version]'0.0.0.0' }
            } -Descending | Select-Object -First 1).FullName
            Write-Host "[build-msix] makeappx found via Windows Kits glob: $makeappx"
        }
    }
}

if ($null -eq $makeappx -or -not (Test-Path $makeappx)) {
    Write-Host "[build-msix] FAIL: makeappx.exe not found." -ForegroundColor Red
    Write-Host "[build-msix]   Install the Windows SDK (Windows App Certification Kit component)."
    Write-Host "[build-msix]   Typical path: C:\Program Files (x86)\Windows Kits\10\bin\10.0.*\x64\makeappx.exe"
    # Cleanup staging before exit
    Remove-Item $stagingDir -Recurse -Force -ErrorAction SilentlyContinue
    exit 1
}

# ---------------------------------------------------------------------------
# Step 5/5 — Pack
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host '[build-msix] --- Step 5/5: Pack ---'

$msixOut = Join-Path $outDir 'PassKee.Provider.msix'

& $makeappx pack /v /o /d $stagingDir /p $msixOut
$makeappxExit = $LASTEXITCODE

# Always clean up staging, regardless of outcome.
Write-Host "[build-msix] Removing staging directory: $stagingDir"
Remove-Item $stagingDir -Recurse -Force -ErrorAction SilentlyContinue

if ($makeappxExit -ne 0) {
    Write-Host "[build-msix] FAIL: makeappx exited with code $makeappxExit" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $msixOut)) {
    Write-Host "[build-msix] FAIL: makeappx reported success but $msixOut was not created." -ForegroundColor Red
    exit 1
}

$msixSize = (Get-Item $msixOut).Length
Write-Host ''
Write-Host "[build-msix] PASS out\PassKee.Provider.msix $msixSize bytes" -ForegroundColor Green
exit 0
