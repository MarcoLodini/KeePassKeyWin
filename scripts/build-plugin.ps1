#Requires -Version 5.1
<#
.SYNOPSIS
    Builds PassKee.Plugin (net48) and copies it into the KeePass Plugins directory.

.PARAMETER KeePassDir
    Path to the KeePass 2.x installation directory.
    Default: "C:\Program Files\KeePass Password Safe 2"

.PARAMETER PluginDir
    Path to the Plugins subdirectory inside KeePassDir.
    Default: "<KeePassDir>\Plugins"

.PARAMETER Configuration
    Build configuration: Debug or Release. Default: Debug.

.PARAMETER DryRun
    Print what would be copied without actually copying anything.

.EXAMPLE
    .\scripts\build-plugin.ps1
    .\scripts\build-plugin.ps1 -KeePassDir "C:\Tools\KeePass" -DryRun
    .\scripts\build-plugin.ps1 -Configuration Release
#>
[CmdletBinding()]
param(
    [string] $KeePassDir   = "C:\Program Files\KeePass Password Safe 2",
    [string] $PluginDir    = "",
    [ValidateSet("Debug","Release")]
    [string] $Configuration = "Debug",
    [switch] $DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# --- Resolve paths ---
$repoRoot = Split-Path -Parent $PSScriptRoot

if (-not (Test-Path $KeePassDir)) {
    throw "KeePass directory not found: '$KeePassDir'. " +
          "Install KeePass or pass -KeePassDir to the correct path."
}

$keepassExe = Join-Path $KeePassDir "KeePass.exe"
if (-not (Test-Path $keepassExe)) {
    throw "KeePass.exe not found at '$keepassExe'. Is KeePassDir correct?"
}

if ([string]::IsNullOrEmpty($PluginDir)) {
    $PluginDir = Join-Path $KeePassDir "Plugins"
}

# --- Architecture check ---
# KeePass 2.x is commonly distributed as 32-bit; warn if the machine differs.
$peHeader = [System.IO.File]::ReadAllBytes($keepassExe)
# PE machine type is at offset 0x3C (PE header offset), then +4 bytes for Machine field.
$peOffset  = [BitConverter]::ToInt32($peHeader, 0x3C)
$machineId = [BitConverter]::ToUInt16($peHeader, $peOffset + 4)
$machineStr = switch ($machineId) {
    0x014C { "x86 (32-bit)" }
    0x8664 { "x64 (64-bit)" }
    0xAA64 { "ARM64" }
    default { "unknown (0x{0:X4})" -f $machineId }
}
Write-Host "[build-plugin] KeePass.exe architecture: $machineStr"
# PassKee.dll is AnyCPU so it adapts — no hard block, just information.

# --- Build ---
$pluginCsproj = Join-Path $repoRoot "src\PassKee.Plugin\PassKee.Plugin.csproj"
if (-not (Test-Path $pluginCsproj)) {
    throw "Project file not found: '$pluginCsproj'. Run this script from the repo root or a scripts\ subdirectory."
}

Write-Host "[build-plugin] Building PassKee.Plugin ($Configuration, net48)..."
$buildArgs = @(
    "build", $pluginCsproj,
    "-f", "net48",
    "-c", $Configuration,
    "/p:KeePassDir=$KeePassDir",
    "--nologo"
)
& dotnet @buildArgs
if ($LASTEXITCODE -ne 0) { throw "dotnet build failed (exit $LASTEXITCODE)." }

# --- Collect outputs ---
$srcDir = Join-Path $repoRoot "src\PassKee.Plugin\bin\$Configuration\net48"
$filesToCopy = @(
    "PassKee.dll",
    "Newtonsoft.Json.dll"
)

foreach ($f in $filesToCopy) {
    $src = Join-Path $srcDir $f
    if (-not (Test-Path $src)) {
        Write-Warning "File not found in build output, skipping: $src"
        continue
    }
    $dst = Join-Path $PluginDir $f
    if ($DryRun) {
        Write-Host "[DryRun] Would copy: $src -> $dst"
    } else {
        if (-not (Test-Path $PluginDir)) {
            Write-Host "[build-plugin] Creating plugin directory: $PluginDir"
            New-Item -ItemType Directory -Path $PluginDir -Force | Out-Null
        }
        Write-Host "[build-plugin] Copying $f -> $PluginDir"
        Copy-Item $src $dst -Force
    }
}

if ($DryRun) {
    Write-Host "[build-plugin] Dry run complete — nothing was copied."
} else {
    Write-Host "[build-plugin] Done. Restart KeePass to pick up the updated plugin."
}
