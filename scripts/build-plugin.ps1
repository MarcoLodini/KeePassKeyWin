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

# Split Core and Plugin into separate `dotnet build` invocations to avoid the
# \\wsl.localhost SMB/9P cache race that surfaces as CS0006 "Metadata file
# 'PassKee.Core.dll' could not be found" when both projects build in one
# MSBuild process on a WSL2 repo. Cross-process + Test-Path poll gives the
# SMB layer time to surface the Core DLL before the Plugin consumes it.
$passKeeCoreCsproj = Join-Path $repoRoot "src\PassKee.Core\PassKee.Core.csproj"
$passKeeCoreDll    = Join-Path $repoRoot "src\PassKee.Core\bin\$Configuration\net48\PassKee.Core.dll"

Write-Host "[build-plugin] Building PassKee.Core ($Configuration, net48)..."
& dotnet build $passKeeCoreCsproj -f net48 -c $Configuration --nologo
if ($LASTEXITCODE -ne 0) { throw "PassKee.Core build failed (exit $LASTEXITCODE)." }

$coreDllDeadline = (Get-Date).AddSeconds(15)
while ((Get-Date) -lt $coreDllDeadline) {
    if (Test-Path $passKeeCoreDll) { break }
    Start-Sleep -Milliseconds 200
}
if (-not (Test-Path $passKeeCoreDll)) {
    throw "PassKee.Core.dll did not become visible at $passKeeCoreDll within 15s (WSL<->Windows FS sync stall)."
}

Write-Host "[build-plugin] Building PassKee.Plugin ($Configuration, net48)..."
$buildArgs = @(
    "build", $pluginCsproj,
    "-f", "net48",
    "-c", $Configuration,
    "/p:KeePassDir=$KeePassDir",
    "--no-dependencies",
    "--nologo"
)
& dotnet @buildArgs
if ($LASTEXITCODE -ne 0) { throw "dotnet build failed (exit $LASTEXITCODE)." }

# --- Collect outputs ---
# Copy every DLL from the plugin build output. PassKee.dll depends on
# PassKee.Core.dll, Newtonsoft.Json.dll, and System.Memory's polyfill family
# (System.Buffers, System.Numerics.Vectors, System.Runtime.CompilerServices.Unsafe);
# missing any of them makes KeePass silently reject the plugin at load time.
$srcDir = Join-Path $repoRoot "src\PassKee.Plugin\bin\$Configuration\net48"
$dlls   = @(Get-ChildItem -Path $srcDir -Filter "*.dll" -File)
if ($dlls.Count -eq 0) {
    throw "No DLLs found in build output: $srcDir"
}

if (-not $DryRun -and -not (Test-Path $PluginDir)) {
    Write-Host "[build-plugin] Creating plugin directory: $PluginDir"
    New-Item -ItemType Directory -Path $PluginDir -Force | Out-Null
}

foreach ($dll in $dlls) {
    $dst = Join-Path $PluginDir $dll.Name
    if ($DryRun) {
        Write-Host "[DryRun] Would copy: $($dll.FullName) -> $dst"
    } else {
        Write-Host "[build-plugin] Copying $($dll.Name) -> $PluginDir"
        Copy-Item $dll.FullName $dst -Force
        # Strip any Mark-of-the-Web a WSL2 <-> Windows copy may have attached.
        Unblock-File -Path $dst -ErrorAction SilentlyContinue
    }
}

if ($DryRun) {
    Write-Host "[build-plugin] Dry run complete — nothing was copied."
} else {
    Write-Host "[build-plugin] Done. Restart KeePass to pick up the updated plugin."
}
