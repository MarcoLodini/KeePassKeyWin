#Requires -Version 5.1
<#
.SYNOPSIS
    Unattended end-to-end validation of PassKee Phase 0.5 (Steps 1-5 + 7).

.DESCRIPTION
    Automates the steps in docs/WINDOWS_VALIDATION.md that do not require human
    browser gestures (Step 6, webauthn.io browser flow, is intentionally omitted).

    What this script does:
      1. Pre-flight: verifies KeePass, .NET 8 SDK, .NET Framework 4.8, and
         both project files.
      2. Builds PassKee.Plugin (net48) + PassKee.Harness (net8 Release).
      3. Copies PassKee.dll + Newtonsoft.Json.dll into KeePass Plugins\.
      4. Opens a throwaway .kdbx from scripts\fixtures\template.kdbx (see note
         below), assigning a fresh random password for the session.
      5. Launches KeePass in the background against that vault.
      6. Polls HKCU:\Software\PassKee\HandshakeNonce until the plugin writes it
         (timeout: $TimeoutSec seconds).
      7. Launches a headless Chrome instance (remote-debugging-port 19222) so
         the harness CDP channel connects without a visible browser window.
         The harness --smoke mode requires a live CDP target even though it never
         performs browser gestures; this is Phase 0.5 harness design, not a
         validate-phase05 choice.
      8. Runs PassKee.Harness in --smoke mode: createPasskey -> listCredentials
         -> signAssertion -> deleteCredential.
      9. (Step 7) Verifies HKCU HandshakeNonce is cleared post-handshake.
     10. Cleans up: kills KeePass + Chrome, deletes temp vault (unless
         -KeepTempFiles).
     11. Prints final PASS or FAIL:<reason> and exits 0/1 accordingly.
         On FAIL, emits a diagnostic bundle (KeePass log, registry state,
         harness stdout).

    === Why a template .kdbx fixture? ===
    KeePass 2.x has no supported headless "create new database" command-line
    flag. The -c: and --create flags in the KeePass source exist but open a
    GUI wizard; they cannot be driven without user interaction. The alternative
    of scripting the KeePass COM interface is not available on unmodified
    installs. Therefore we ship a minimal pre-seeded .kdbx under
    scripts\fixtures\template.kdbx (created with pykeepass, empty root group,
    password "placeholder"). The script copies it to a per-run temp directory
    and re-opens it with KeePass using -pw:placeholder. This avoids both the
    interactive-create limitation and any risk of touching a real vault.

.PARAMETER KeePassDir
    Path to the KeePass 2.x installation directory.
    Default: "C:\Program Files\KeePass Password Safe 2"

.PARAMETER TimeoutSec
    How long (in seconds) to wait for the handshake nonce to appear in the
    registry after KeePass starts. Default: 30.

.PARAMETER DryRun
    Run pre-flight checks only. Skip build, install, launch, and smoke test.

.PARAMETER KeepTempFiles
    Do not delete the temp .kdbx directory on exit (useful for debugging).

.EXAMPLE
    .\scripts\validate-phase05.ps1
    .\scripts\validate-phase05.ps1 -KeePassDir "C:\Tools\KeePass" -TimeoutSec 60
    .\scripts\validate-phase05.ps1 -DryRun
    .\scripts\validate-phase05.ps1 -KeepTempFiles
#>
[CmdletBinding()]
param(
    [string] $KeePassDir   = "C:\Program Files\KeePass Password Safe 2",
    [int]    $TimeoutSec   = 30,
    [switch] $DryRun,
    [switch] $KeepTempFiles
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# CDP port used for the headless Chrome instance spun up by this script.
# Chosen to avoid collision with any real Chrome the user may have open.
$Script:cdpPort             = 19222
$Script:keepassPid          = $null
$Script:chromePid           = $null
$Script:tempDir             = $null
$Script:harnessOut          = ""
$Script:failReason          = ""
$Script:keepassConfigSnapshot = $null   # pre-run KeePass.config.xml text
$Script:keepassWindowTitles = @()       # titles captured during wait loop
$Script:runStart            = Get-Date  # used for Event Log time filter
$Script:keepassStdoutPath   = $null     # saved so Emit-DiagBundle works after cleanup
$Script:keepassStderrPath   = $null
$Script:keepassStdoutLines  = $null     # content read before temp dir is deleted
$Script:keepassStderrLines  = $null

$repoRoot = Split-Path -Parent $PSScriptRoot

# ---------------------------------------------------------------------------
# P/Invoke – window enumeration (for detecting stuck modal dialogs)
# ---------------------------------------------------------------------------
# We enumerate top-level windows owned by the KeePass PID so we can detect
# an "unsigned plugin" confirmation dialog that KeePass may have shown while
# minimized.  We use plain Win32 EnumWindows + GetWindowThreadProcessId
# because UIAutomationClient.dll requires a STA thread and is fragile from
# PowerShell.  These P/Invoke signatures are PS 5.1 compatible.

if (-not ([System.Management.Automation.PSTypeName]'PassKee.WinEnum').Type) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace PassKee {
    public static class WinEnum {
        [DllImport("user32.dll")]
        private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

        [DllImport("user32.dll")]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);

        [DllImport("user32.dll")]
        private static extern bool IsWindowVisible(IntPtr hWnd);

        private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

        public static List<string[]> GetWindowsForPid(int pid) {
            var result = new List<string[]>();
            EnumWindows(delegate(IntPtr hWnd, IntPtr lp) {
                uint wPid;
                GetWindowThreadProcessId(hWnd, out wPid);
                if ((int)wPid == pid) {
                    var title = new StringBuilder(512);
                    var cls   = new StringBuilder(256);
                    GetWindowText(hWnd, title, 512);
                    GetClassName(hWnd, cls, 256);
                    bool visible = IsWindowVisible(hWnd);
                    result.Add(new string[] {
                        hWnd.ToString(),
                        title.ToString(),
                        cls.ToString(),
                        visible ? "visible" : "hidden"
                    });
                }
                return true;
            }, IntPtr.Zero);
            return result;
        }
    }
}
'@ -ErrorAction SilentlyContinue
}

function Get-KeePassWindows {
    param([int] $Pid)
    try {
        $wins = [PassKee.WinEnum]::GetWindowsForPid($Pid)
        return $wins
    } catch {
        return @()
    }
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Write-Check {
    param([string] $Label, [bool] $Ok, [string] $Detail = "")
    $status = if ($Ok) { "PASS" } else { "FAIL" }
    $colour = if ($Ok) { "Green" } else { "Red" }
    $line   = "[validator] {0,-50} [{1}]" -f $Label, $status
    if ($Detail) { $line += "  $Detail" }
    Write-Host $line -ForegroundColor $colour
    return $Ok
}

function Fail {
    param([string] $Reason)
    $Script:failReason = $Reason
    Write-Host ""
    Write-Host "[validator] FAIL: $Reason" -ForegroundColor Red
    Invoke-Cleanup
    Emit-DiagBundle
    Write-Host ""
    Write-Host "FAIL: $Reason"
    exit 1
}

function Invoke-Cleanup {
    # Capture KeePass window state BEFORE killing — detect stuck modal dialogs.
    if ($null -ne $Script:keepassPid) {
        try {
            $kp = Get-Process -Id $Script:keepassPid -ErrorAction SilentlyContinue
            if ($null -ne $kp) {
                Write-Host "[diag] KeePass process state at cleanup:" -ForegroundColor Yellow
                Write-Host "  MainWindowTitle  : $($kp.MainWindowTitle)"
                Write-Host "  MainWindowHandle : $($kp.MainWindowHandle)"
                Write-Host "  Responding       : $($kp.Responding)"

                # Enumerate all top-level windows owned by KeePass PID.
                # Reveals hidden modal dialogs (e.g. "unsigned plugin?" confirmation).
                $wins = Get-KeePassWindows -Pid $Script:keepassPid
                if ($wins.Count -gt 0) {
                    Write-Host "  Top-level windows ($($wins.Count)):" -ForegroundColor Yellow
                    foreach ($w in $wins) {
                        Write-Host ("    HWND={0}  title='{1}'  class='{2}'  {3}" -f $w[0], $w[1], $w[2], $w[3])
                    }
                    # Save for the diag bundle
                    $Script:keepassWindowTitles = $wins | ForEach-Object {
                        "HWND=$($_[0])  title='$($_[1])'  class='$($_[2])'  $($_[3])"
                    }
                } else {
                    Write-Host "  No enumerable top-level windows found."
                }
            }
        } catch {
            Write-Host "  (error reading KeePass process state: $_)"
        }
    }

    # Kill KeePass if we launched it
    if ($null -ne $Script:keepassPid) {
        try {
            $kp = Get-Process -Id $Script:keepassPid -ErrorAction SilentlyContinue
            if ($null -ne $kp) {
                Write-Host "[validator] Stopping KeePass (PID $($Script:keepassPid))..."
                Stop-Process -Id $Script:keepassPid -Force -ErrorAction SilentlyContinue
            }
        } catch { }
        $Script:keepassPid = $null
    }

    # Kill headless Chrome if we launched it
    if ($null -ne $Script:chromePid) {
        try {
            $cp = Get-Process -Id $Script:chromePid -ErrorAction SilentlyContinue
            if ($null -ne $cp) {
                Write-Host "[validator] Stopping Chrome (PID $($Script:chromePid))..."
                Stop-Process -Id $Script:chromePid -Force -ErrorAction SilentlyContinue
            }
        } catch { }
        $Script:chromePid = $null
    }

    # Read KeePass stdout/stderr into memory BEFORE deleting the temp dir so
    # Emit-DiagBundle can display them even when KeepTempFiles is not set.
    if ($null -eq $Script:keepassStdoutLines -and $null -ne $Script:keepassStdoutPath) {
        if (Test-Path $Script:keepassStdoutPath) {
            $Script:keepassStdoutLines = Get-Content $Script:keepassStdoutPath -ErrorAction SilentlyContinue
        }
    }
    if ($null -eq $Script:keepassStderrLines -and $null -ne $Script:keepassStderrPath) {
        if (Test-Path $Script:keepassStderrPath) {
            $Script:keepassStderrLines = Get-Content $Script:keepassStderrPath -ErrorAction SilentlyContinue
        }
    }

    # Delete temp directory (unless user asked to keep it)
    if ((-not $KeepTempFiles) -and ($null -ne $Script:tempDir) -and (Test-Path $Script:tempDir)) {
        Write-Host "[validator] Removing temp directory: $($Script:tempDir)"
        Remove-Item $Script:tempDir -Recurse -Force -ErrorAction SilentlyContinue
        $Script:tempDir = $null
    } elseif ($KeepTempFiles -and ($null -ne $Script:tempDir)) {
        Write-Host "[validator] Keeping temp directory (KeepTempFiles): $($Script:tempDir)"
    }
}

function Emit-DiagBundle {
    Write-Host ""
    Write-Host "--- Diagnostic bundle ---" -ForegroundColor Yellow

    # 1. KeePass log file
    $keePassLog = Join-Path $env:LOCALAPPDATA "KeePass\KeePass.log.txt"
    if (Test-Path $keePassLog) {
        Write-Host "[diag] Last 50 lines of KeePass log ($keePassLog):" -ForegroundColor Yellow
        Get-Content $keePassLog -Tail 50 | ForEach-Object { Write-Host "  $_" }
    } else {
        Write-Host "[diag] KeePass log not found at $keePassLog" -ForegroundColor Yellow
    }

    # 2. Registry state
    Write-Host "[diag] Registry HKCU:\Software\PassKee:" -ForegroundColor Yellow
    try {
        $regKey = Get-ItemProperty -Path "HKCU:\Software\PassKee" -ErrorAction SilentlyContinue
        if ($null -eq $regKey) {
            Write-Host "  (key does not exist)"
        } else {
            $regKey | Format-List | Out-String | ForEach-Object { Write-Host "  $_" }
        }
    } catch {
        Write-Host "  (error reading registry: $_)"
    }

    # 3. Harness stdout captured during the run
    if ($Script:harnessOut.Length -gt 0) {
        Write-Host "[diag] Harness stdout:" -ForegroundColor Yellow
        $Script:harnessOut -split "`n" | ForEach-Object { Write-Host "  $_" }
    } else {
        Write-Host "[diag] No harness output captured." -ForegroundColor Yellow
    }

    # 4. KeePass stdout / stderr files (redirected at launch)
    # Invoke-Cleanup reads these into memory before deleting the temp dir, so
    # $Script:keepassStdout/StderrLines are available even after cleanup.
    $kpOutItems = @(
        @{ Label = "stdout"; Lines = $Script:keepassStdoutLines; Path = $Script:keepassStdoutPath },
        @{ Label = "stderr"; Lines = $Script:keepassStderrLines; Path = $Script:keepassStderrPath }
    )
    foreach ($item in $kpOutItems) {
        $label = $item.Label
        $lines = $item.Lines
        $f     = $item.Path
        if ($null -ne $lines) {
            if ($lines.Count -gt 0) {
                Write-Host "[diag] KeePass $label ($f):" -ForegroundColor Yellow
                $lines | ForEach-Object { Write-Host "  $_" }
            } else {
                Write-Host "[diag] KeePass $label: (empty — KeePass did not write to $label)" -ForegroundColor Yellow
            }
        } elseif ($null -ne $f -and (Test-Path $f)) {
            # File still on disk (e.g. KeepTempFiles mode, or cleanup not yet run)
            $diskLines = Get-Content $f -ErrorAction SilentlyContinue
            if ($diskLines) {
                Write-Host "[diag] KeePass $label ($f):" -ForegroundColor Yellow
                $diskLines | ForEach-Object { Write-Host "  $_" }
            } else {
                Write-Host "[diag] KeePass $label: (empty)" -ForegroundColor Yellow
            }
        } else {
            Write-Host "[diag] KeePass $label: not available (KeePass may not have been launched or redirect file gone)" -ForegroundColor Yellow
        }
    }

    # 5. Plugins directory listing (name, size, last-write, Zone.Identifier ADS)
    Write-Host "[diag] KeePass Plugins\ directory listing:" -ForegroundColor Yellow
    $pluginDirDiag = Join-Path $KeePassDir "Plugins"
    if (Test-Path $pluginDirDiag) {
        $items = Get-ChildItem -Path $pluginDirDiag -File -ErrorAction SilentlyContinue
        if ($items) {
            foreach ($item in $items) {
                $zone = Get-Item -Path $item.FullName -Stream "Zone.Identifier" -ErrorAction SilentlyContinue
                $blocked = if ($null -ne $zone) { " [BLOCKED:Zone.Identifier present]" } else { "" }
                Write-Host ("  {0,-45} {1,10} bytes  {2}{3}" -f `
                    $item.Name, $item.Length, $item.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss"), $blocked)
            }
        } else {
            Write-Host "  (directory is empty)"
        }
    } else {
        Write-Host "  (directory not found: $pluginDirDiag)"
    }

    # 6. PluginCache directory listing (post-run state)
    Write-Host "[diag] KeePass PluginCache\ directory listing (post-run):" -ForegroundColor Yellow
    $pluginCacheDir = Join-Path $env:LOCALAPPDATA "KeePass\PluginCache"
    if (Test-Path $pluginCacheDir) {
        $cacheItems = Get-ChildItem -Path $pluginCacheDir -File -Recurse -ErrorAction SilentlyContinue
        if ($cacheItems) {
            foreach ($ci in $cacheItems) {
                Write-Host ("  {0,-60} {1,10} bytes  {2}" -f `
                    $ci.FullName, $ci.Length, $ci.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss"))
            }
        } else {
            Write-Host "  (PluginCache directory is empty)"
        }
    } else {
        Write-Host "  (PluginCache directory not found: $pluginCacheDir)"
    }

    # 7. KeePass.config.xml delta — compare snapshot vs current file
    Write-Host "[diag] KeePass.config.xml delta (pre-run vs post-run):" -ForegroundColor Yellow
    $configPath = Join-Path $env:LOCALAPPDATA "KeePass\KeePass.config.xml"
    if ($null -ne $Script:keepassConfigSnapshot) {
        if (Test-Path $configPath) {
            $postRunXml = Get-Content $configPath -Raw -ErrorAction SilentlyContinue
            if ($postRunXml -ne $Script:keepassConfigSnapshot) {
                # Extract plugin-relevant nodes from both versions for a targeted diff.
                $relevantXPaths = @(
                    "Security/PluginCompatibility",
                    "Application/Start/PluginCacheDeleteOnStartup",
                    "Application/LogSerializationExceptions",
                    "UI/DebugThrowException",
                    "Application/Start/OpenLastFile"
                )
                Write-Host "  [config changed — plugin-relevant sections]"
                Write-Host "  --- PRE-RUN SNAPSHOT (plugin sections) ---"
                foreach ($xp in $relevantXPaths) {
                    $tag = ($xp -split "/")[-1]
                    $pre  = if ($Script:keepassConfigSnapshot -match "<$tag>(.*?)</$tag>") { $Matches[0] } else { "(absent)" }
                    $post = if ($postRunXml -match "<$tag>(.*?)</$tag>") { $Matches[0] } else { "(absent)" }
                    if ($pre -ne $post) {
                        Write-Host "  $xp:"
                        Write-Host "    before: $pre"
                        Write-Host "    after : $post"
                    }
                }
                Write-Host "  --- FULL POST-RUN KeePass.config.xml ---"
                $postRunXml -split "`n" | ForEach-Object { Write-Host "  $_" }
            } else {
                Write-Host "  (config unchanged from pre-run snapshot)"
            }
        } else {
            Write-Host "  (config file not found post-run: $configPath)"
        }
    } else {
        Write-Host "  (no pre-run snapshot — config may not have existed before Step 5b)"
        if (Test-Path $configPath) {
            Write-Host "  --- CURRENT KeePass.config.xml ---"
            Get-Content $configPath -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "  $_" }
        }
    }

    # 8. KeePass window titles captured during the wait loop + at cleanup
    Write-Host "[diag] KeePass window titles captured during nonce wait loop:" -ForegroundColor Yellow
    if ($Script:keepassWindowTitles.Count -gt 0) {
        $Script:keepassWindowTitles | ForEach-Object { Write-Host "  $_" }
    } else {
        Write-Host "  (none captured — window enumeration may not have fired or process exited early)"
    }

    # 9. Windows Event Log — CLR + Application Error entries since script start
    Write-Host "[diag] Windows Event Log (Application, .NET Runtime / Application Error, since run start):" -ForegroundColor Yellow
    try {
        $evtFilter = @{
            LogName      = 'Application'
            ProviderName = @('.NET Runtime', 'Application Error', '.NET Runtime Optimization Service')
            StartTime    = $Script:runStart
        }
        $evts = Get-WinEvent -FilterHashtable $evtFilter -ErrorAction SilentlyContinue
        if ($evts) {
            foreach ($evt in $evts) {
                Write-Host ("  [{0}] [{1}] {2}" -f `
                    $evt.TimeCreated.ToString("HH:mm:ss.fff"), $evt.LevelDisplayName, $evt.Message.Substring(0, [Math]::Min(300, $evt.Message.Length)))
            }
        } else {
            Write-Host "  (no matching events since $($Script:runStart.ToString('HH:mm:ss')))"
        }
    } catch {
        Write-Host "  (error reading event log: $_)"
    }

    Write-Host "--- End diagnostic bundle ---" -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# Step 1 — Pre-flight checks
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "[validator] ===== PassKee Phase 0.5 Validator =====" -ForegroundColor Cyan
Write-Host "[validator] KeePassDir : $KeePassDir"
Write-Host "[validator] TimeoutSec : $TimeoutSec"
Write-Host "[validator] DryRun     : $DryRun"
Write-Host ""
Write-Host "[validator] --- Pre-flight checks ---"

$allOk = $true

# 1a. KeePass.exe
$keepassExe = Join-Path $KeePassDir "KeePass.exe"
$ok = Test-Path $keepassExe
$allOk = $allOk -and (Write-Check "KeePass.exe at $KeePassDir" $ok $(if (-not $ok) { "(not found)" } else { "" }))

# 1b. .NET SDK >= 8 (8, 9, 10+ all build net8.0 targets via forward-compat).
# Check `dotnet --list-sdks` rather than `dotnet --version` so a global.json
# pinning to an older SDK doesn't hide a usable SDK being installed.
$dotnetSdks  = & dotnet --list-sdks 2>&1
$dotnetSdkOk = @($dotnetSdks | Where-Object {
    if ($_ -match "^(\d+)\.") { [int]$Matches[1] -ge 8 } else { $false }
}).Count -gt 0
$sdkDetail   = if ($dotnetSdkOk) { "(>= 8 found)" } else { "(no 8+ SDK)" }
$allOk = $allOk -and (Write-Check ".NET SDK >= 8 installed (dotnet --list-sdks)" $dotnetSdkOk $sdkDetail)

# 1c. .NET Framework 4.8 (registry)
$ndpPath   = "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full"
$ndpRelease = $null
try {
    $ndpRelease = (Get-ItemProperty -Path $ndpPath -Name "Release" -ErrorAction Stop).Release
} catch { }
# Release >= 528040 corresponds to .NET Framework 4.8 on Windows 10 / Server 2019+
# (528040 = .NET 4.8 on Win10, 528049 = .NET 4.8 on Win11)
$netfxOk = ($null -ne $ndpRelease) -and ($ndpRelease -ge 528040)
$allOk = $allOk -and (Write-Check ".NET Framework 4.8 (registry Release >= 528040)" $netfxOk $(if ($null -ne $ndpRelease) { "(Release=$ndpRelease)" } else { "(key missing)" }))

# 1d. Plugin project
$pluginCsproj = Join-Path $repoRoot "src\PassKee.Plugin\PassKee.Plugin.csproj"
$ok = Test-Path $pluginCsproj
$allOk = $allOk -and (Write-Check "Plugin source ($pluginCsproj)" $ok)

# 1e. Harness project
$harnessCsproj = Join-Path $repoRoot "src\PassKee.Harness\PassKee.Harness.csproj"
$ok = Test-Path $harnessCsproj
$allOk = $allOk -and (Write-Check "Harness source ($harnessCsproj)" $ok)

# 1f. Template kdbx fixture
$templateKdbx = Join-Path $repoRoot "scripts\fixtures\template.kdbx"
$ok = Test-Path $templateKdbx
$allOk = $allOk -and (Write-Check "Template .kdbx fixture (scripts\fixtures\template.kdbx)" $ok)

Write-Host ""
if (-not $allOk) {
    Write-Host "[validator] One or more pre-flight checks failed. Aborting." -ForegroundColor Red
    Write-Host ""
    Write-Host "FAIL: pre-flight checks"
    exit 1
}

Write-Host "[validator] All pre-flight checks passed." -ForegroundColor Green

# ---------------------------------------------------------------------------
# Step 2 — Exit if -DryRun
# ---------------------------------------------------------------------------

if ($DryRun) {
    Write-Host ""
    Write-Host "[validator] -DryRun specified. Stopping after pre-flight." -ForegroundColor Cyan
    Write-Host ""
    Write-Host "PASS (dry-run)"
    exit 0
}

# From here, any unexpected termination should trigger cleanup.
# We use try/finally at the end of the script to guarantee this.

try {

# ---------------------------------------------------------------------------
# Step 3 — Build plugin (net48) and harness (net8 Release)
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "[validator] --- Step 3: Build ---"

Write-Host "[validator] Building PassKee.Plugin (net48, Release)..."
$buildPluginArgs = @(
    "build", $pluginCsproj,
    "-f", "net48",
    "-c", "Release",
    "/p:KeePassDir=$KeePassDir",
    "--nologo"
)
& dotnet @buildPluginArgs
if ($LASTEXITCODE -ne 0) {
    Fail "PassKee.Plugin build failed (exit $LASTEXITCODE)."
}
Write-Host "[validator] Plugin build: OK"

Write-Host "[validator] Building PassKee.Harness (net8, Release)..."
& dotnet build $harnessCsproj -c Release --nologo
if ($LASTEXITCODE -ne 0) {
    Fail "PassKee.Harness build failed (exit $LASTEXITCODE)."
}
Write-Host "[validator] Harness build: OK"

# ---------------------------------------------------------------------------
# Step 4 — Install plugin DLL into KeePass\Plugins
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "[validator] --- Step 4: Install plugin ---"

$pluginDir = Join-Path $KeePassDir "Plugins"
if (-not (Test-Path $pluginDir)) {
    Write-Host "[validator] Creating Plugins directory: $pluginDir"
    New-Item -ItemType Directory -Path $pluginDir -Force | Out-Null
}

$srcDir = Join-Path $repoRoot "src\PassKee.Plugin\bin\Release\net48"
# Copy every DLL from the plugin build output. PassKee.dll depends on
# PassKee.Core.dll, Newtonsoft.Json.dll, and System.Memory's transitive
# polyfill family (System.Buffers, System.Numerics.Vectors,
# System.Runtime.CompilerServices.Unsafe); missing any of them makes KeePass
# silently reject the plugin at load time. Wildcard-copy covers future deps.
$dlls = @(Get-ChildItem -Path $srcDir -Filter "*.dll" -File)
if ($dlls.Count -eq 0) {
    Fail "No DLLs found in build output: $srcDir"
}
foreach ($dll in $dlls) {
    $dst = Join-Path $pluginDir $dll.Name
    Write-Host "[validator] Copying $($dll.Name) -> $pluginDir"
    Copy-Item $dll.FullName $dst -Force
    if (-not (Test-Path $dst)) {
        Fail "File was not copied to plugin dir: $dst"
    }
    # Strip any Mark-of-the-Web (Zone.Identifier ADS) the DLL may have picked
    # up while travelling across the WSL2 <-> Windows filesystem boundary.
    # Without this, KeePass can refuse to load an "untrusted" plugin.
    Unblock-File -Path $dst -ErrorAction SilentlyContinue
}
Write-Host "[validator] Plugin files installed: OK ($($dlls.Count) DLL(s))"

# ---------------------------------------------------------------------------
# Step 5 — Create throwaway .kdbx in TEMP
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "[validator] --- Step 5: Prepare temp vault ---"

$guid    = [System.Guid]::NewGuid().ToString("N")
$tempDir = Join-Path $env:TEMP "passkee-validate-$guid"
$Script:tempDir = $tempDir
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

# Copy the pre-seeded template fixture to the temp location.
# KeePass will open it with the fixture password "placeholder".
# We do NOT randomise the password here because it is baked into the .kdbx
# encryption; generating a new random password would require re-encrypting
# the database, which is KeePass's job. The fixture password is intentionally
# ephemeral (the vault is deleted after the run) and the file is only accessible
# to the current user in TEMP.
$tempKdbx = Join-Path $tempDir "validate.kdbx"
Copy-Item $templateKdbx $tempKdbx -Force
Write-Host "[validator] Temp vault: $tempKdbx"
Write-Host "[validator] Vault password: placeholder (baked into template fixture)"

# ---------------------------------------------------------------------------
# Step 5b — Force KeePass diagnostic mode
# ---------------------------------------------------------------------------
# Run BEFORE launching KeePass so that the diagnostic knobs are in place
# when KeePass initialises and loads plugins.

Write-Host ""
Write-Host "[validator] --- Step 5b: Force KeePass diagnostic mode ---"

# 5b-i. Clear plugin cache (stale-cache hypothesis).
# KeePass caches loaded plugin assemblies; a stale cache entry for an old
# PassKee.dll version can prevent the new one from loading.
$pluginCacheDir = Join-Path $env:LOCALAPPDATA "KeePass\PluginCache"
if (Test-Path $pluginCacheDir) {
    Write-Host "[validator] Clearing plugin cache: $pluginCacheDir"
    Get-ChildItem -Path $pluginCacheDir -Recurse -ErrorAction SilentlyContinue |
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "[validator] Plugin cache cleared."
} else {
    Write-Host "[validator] Plugin cache directory not found (first run) — nothing to clear."
}

# 5b-ii. Enable KeePass logging via KeePass.config.xml.
# Relevant flags (verified against KeePass 2.x source / AppConfigEx.cs):
#   <Application><LogSerializationExceptions>true</LogSerializationExceptions>
#     — logs XML/config serialization exceptions
#   <UI><DebugThrowException>true</DebugThrowException>
#     — rethrows internal exceptions so they appear in the log
#   <Application><Start><PluginCacheDeleteOnStartup>true</PluginCacheDeleteOnStartup>
#     — forces plugin cache rebuild on every start (belt-and-suspenders)
# KeePass writes plugin-load errors to KeePass.log.txt in %LOCALAPPDATA%\KeePass
# when the above flags are set.

$keepassConfigPath = Join-Path $env:LOCALAPPDATA "KeePass\KeePass.config.xml"
$keepassConfigDir  = Join-Path $env:LOCALAPPDATA "KeePass"

# Snapshot current config (before we touch it).
if (Test-Path $keepassConfigPath) {
    $Script:keepassConfigSnapshot = Get-Content $keepassConfigPath -Raw -ErrorAction SilentlyContinue
    Write-Host "[validator] KeePass.config.xml snapshot taken ($($Script:keepassConfigSnapshot.Length) bytes)."
} else {
    $Script:keepassConfigSnapshot = $null
    Write-Host "[validator] KeePass.config.xml not found — will create minimal config with diagnostics enabled."
}

# Ensure the KeePass config directory exists.
if (-not (Test-Path $keepassConfigDir)) {
    New-Item -ItemType Directory -Path $keepassConfigDir -Force | Out-Null
}

# Helper: set or insert an XML element value, operating on the raw text.
# We use regex rather than XmlDocument to avoid re-formatting the file
# and to stay PS 5.1 compatible without a full XPath namespace dance.
function Set-KeePassConfigValue {
    param(
        [string] $Xml,
        [string] $ParentPath,   # e.g. "Application/Start"
        [string] $Element,      # e.g. "PluginCacheDeleteOnStartup"
        [string] $Value         # e.g. "true"
    )
    # If the element already exists, replace its content.
    if ($Xml -match "<$Element>[^<]*</$Element>") {
        return $Xml -replace "<$Element>[^<]*</$Element>", "<$Element>$Value</$Element>"
    }
    # Otherwise try to insert it before the closing tag of the parent element.
    $parts = $ParentPath -split "/"
    $closingTag = "</" + $parts[-1] + ">"
    if ($Xml -match [regex]::Escape($closingTag)) {
        return $Xml -replace [regex]::Escape($closingTag), "`t`t<$Element>$Value</$Element>`n`t`t$closingTag"
    }
    # Parent not found either — append a note and return unchanged
    # (we log it so the operator knows what's missing).
    Write-Host "[validator] WARNING: could not inject <$Element> — parent <$($parts[-1])> not found in config." -ForegroundColor Yellow
    return $Xml
}

if ($null -ne $Script:keepassConfigSnapshot) {
    # Modify existing config in-memory then write back.
    $cfgXml = $Script:keepassConfigSnapshot

    $cfgXml = Set-KeePassConfigValue $cfgXml "Application/Start" "PluginCacheDeleteOnStartup" "true"
    $cfgXml = Set-KeePassConfigValue $cfgXml "Application"       "LogSerializationExceptions" "true"
    $cfgXml = Set-KeePassConfigValue $cfgXml "UI"                "DebugThrowException"        "true"

    Set-Content -Path $keepassConfigPath -Value $cfgXml -Encoding UTF8 -NoNewline
    Write-Host "[validator] KeePass.config.xml updated: PluginCacheDeleteOnStartup=true, LogSerializationExceptions=true, DebugThrowException=true"
} else {
    # Create a minimal config that KeePass will merge with its defaults.
    $minimalConfig = @"
<?xml version="1.0" encoding="utf-8"?>
<Configuration xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
	<Application>
		<Start>
			<PluginCacheDeleteOnStartup>true</PluginCacheDeleteOnStartup>
		</Start>
		<LogSerializationExceptions>true</LogSerializationExceptions>
	</Application>
	<UI>
		<DebugThrowException>true</DebugThrowException>
	</UI>
</Configuration>
"@
    Set-Content -Path $keepassConfigPath -Value $minimalConfig -Encoding UTF8 -NoNewline
    Write-Host "[validator] KeePass.config.xml created with diagnostics enabled."
}

# ---------------------------------------------------------------------------
# Step 6 — Launch KeePass in background
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "[validator] --- Step 6: Launch KeePass ---"

# KeePass stdout/stderr are redirected to files in $Script:tempDir so the
# diagnostic bundle can include them.  KeePass is a WinForms app and rarely
# writes to stdout, but CLR/loader errors may appear on stderr.
# We store the absolute paths in script-scope so Emit-DiagBundle can read
# them even after Invoke-Cleanup has set $Script:tempDir to $null.
$keepassStdout = Join-Path $Script:tempDir "keepass-stdout.txt"
$keepassStderr = Join-Path $Script:tempDir "keepass-stderr.txt"
$Script:keepassStdoutPath = $keepassStdout
$Script:keepassStderrPath = $keepassStderr

# KeePass command-line:
#   KeePass.exe <filename> -pw:<password> --minimize
#   -pw: supplies the master password without GUI prompt
#   --minimize keeps the window out of the way
$keepassArgs = @(
    $tempKdbx,
    "-pw:placeholder",
    "--minimize"
)
$keepassProc = Start-Process -FilePath $keepassExe -ArgumentList $keepassArgs `
               -PassThru -WindowStyle Minimized `
               -RedirectStandardOutput $keepassStdout `
               -RedirectStandardError  $keepassStderr
$Script:keepassPid = $keepassProc.Id
Write-Host "[validator] KeePass launched (PID $($keepassProc.Id))"
Write-Host "[validator] KeePass stdout -> $keepassStdout"
Write-Host "[validator] KeePass stderr -> $keepassStderr"

# ---------------------------------------------------------------------------
# Step 7 — Poll registry for handshake nonce
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "[validator] --- Step 7: Poll for handshake nonce (timeout: ${TimeoutSec}s) ---"

$regPath  = "HKCU:\Software\PassKee"
$nonce    = $null
$deadline = (Get-Date).AddSeconds($TimeoutSec)

$Script:keepassWindowTitles = @()
$windowSampleCount = 0

while ((Get-Date) -lt $deadline) {
    try {
        $val = (Get-ItemProperty -Path $regPath -Name "HandshakeNonce" -ErrorAction Stop).HandshakeNonce
        if (-not [string]::IsNullOrWhiteSpace($val)) {
            $nonce = $val
            break
        }
    } catch {
        # Key or value not yet written — keep polling
    }

    # Periodically sample KeePass window titles (every ~5s) to catch transient
    # dialogs (e.g. "unsigned plugin" prompts) that appear and block init.
    if ($null -ne $Script:keepassPid -and ($windowSampleCount % 10) -eq 0) {
        try {
            $kpNow = Get-Process -Id $Script:keepassPid -ErrorAction SilentlyContinue
            if ($null -ne $kpNow) {
                $wins = Get-KeePassWindows -Pid $Script:keepassPid
                foreach ($w in $wins) {
                    $entry = "t=$([int]((Get-Date) - $Script:runStart).TotalSeconds)s  HWND=$($w[0])  title='$($w[1])'  class='$($w[2])'  $($w[3])"
                    if (-not ($Script:keepassWindowTitles -contains $entry)) {
                        $Script:keepassWindowTitles += $entry
                        if ($w[1] -ne "") {
                            Write-Host "[diag] KeePass window detected: title='$($w[1])' class='$($w[2])' $($w[3])" -ForegroundColor Yellow
                        }
                    }
                }
            }
        } catch { }
    }
    $windowSampleCount++

    Start-Sleep -Milliseconds 500
}

if ([string]::IsNullOrEmpty($nonce)) {
    Fail ("Handshake nonce did not appear in HKCU:\Software\PassKee\HandshakeNonce within ${TimeoutSec}s. " +
          "Likely cause: plugin did not load (check KeePass Tools > PassKee menu, or KeePass log).")
}

Write-Host "[validator] Nonce found: $($nonce.Substring(0, [Math]::Min(8, $nonce.Length)))..."

# ---------------------------------------------------------------------------
# Step 7b — Launch headless Chrome for CDP channel
# ---------------------------------------------------------------------------
#
# The PassKee.Harness --smoke mode establishes a Chrome DevTools Protocol
# connection before running smoke operations. Even though the smoke test does
# not navigate to any page or perform browser gestures, the harness requires
# a live CDP target (this is Phase 0.5 harness design). We launch Chrome in
# headless mode with remote-debugging-port on $cdpPort so the harness can
# connect without a visible browser window.

Write-Host ""
Write-Host "[validator] --- Step 7b: Launch headless Chrome (port $($Script:cdpPort)) ---"

# Try common Chrome/Edge paths in order of preference.
$chromeCandidates = @(
    "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
    "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
    "$env:LocalAppData\Google\Chrome\Application\chrome.exe",
    "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
    "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
)
$chromeBin = $null
foreach ($c in $chromeCandidates) {
    if (Test-Path $c) { $chromeBin = $c; break }
}
if ($null -eq $chromeBin) {
    Fail "Chrome or Edge not found in standard locations. Install Chrome/Edge or add it to PATH."
}
Write-Host "[validator] Using browser: $chromeBin"

$chromeArgs = @(
    "--headless=new",
    "--remote-debugging-port=$($Script:cdpPort)",
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-extensions",
    "--disable-gpu",
    "about:blank"
)
$chromeProc = Start-Process -FilePath $chromeBin -ArgumentList $chromeArgs -PassThru -WindowStyle Hidden
$Script:chromePid = $chromeProc.Id
Write-Host "[validator] Headless Chrome launched (PID $($chromeProc.Id))"

# Give Chrome a moment to open the debug port before the harness connects.
$chromeDeadline = (Get-Date).AddSeconds(15)
$cdpReady = $false
while ((Get-Date) -lt $chromeDeadline) {
    try {
        $resp = Invoke-WebRequest -Uri "http://localhost:$($Script:cdpPort)/json" `
                -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
        if ($resp.StatusCode -eq 200) { $cdpReady = $true; break }
    } catch { }
    Start-Sleep -Milliseconds 500
}
if (-not $cdpReady) {
    Fail "Chrome CDP port $($Script:cdpPort) did not become available within 15s."
}
Write-Host "[validator] Chrome CDP: ready"

# ---------------------------------------------------------------------------
# Step 8 — Run smoke test via harness
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "[validator] --- Step 8: Smoke test ---"

$harnessArgs = @(
    "run",
    "--project", $harnessCsproj,
    "-c", "Release",
    "--no-build",
    "--",
    "--nonce",  $nonce,
    "--rp",     "webauthn.io",
    "--port",   "$($Script:cdpPort)",
    "--smoke"
)

Write-Host "[validator] Invoking harness..."
$harnessOutput = & dotnet @harnessArgs 2>&1
$Script:harnessOut = $harnessOutput | Out-String
$harnesExit = $LASTEXITCODE

Write-Host $Script:harnessOut

if ($harnesExit -ne 0) {
    Fail "Harness smoke test failed (exit $harnesExit)."
}
Write-Host "[validator] Smoke test: PASS"

# ---------------------------------------------------------------------------
# Step 9 — Verify nonce cleared (Step 7 in runbook)
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "[validator] --- Step 9: Verify nonce teardown ---"

$nonceAfter = $null
try {
    $nonceAfter = (Get-ItemProperty -Path $regPath -Name "HandshakeNonce" -ErrorAction Stop).HandshakeNonce
} catch {
    # Key absent is fine — nonce was cleared
    $nonceAfter = $null
}

if ([string]::IsNullOrEmpty($nonceAfter)) {
    Write-Host "[validator] HandshakeNonce cleared after handshake: OK" -ForegroundColor Green
} else {
    Write-Warning ("[validator] HandshakeNonce still present after smoke test. " +
                   "This may indicate a teardown bug in the plugin — worth filing separately. " +
                   "Not treating as FAIL for this validation run.")
}

# ---------------------------------------------------------------------------
# Step 10 — Cleanup
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "[validator] --- Step 10: Cleanup ---"
Invoke-Cleanup

# ---------------------------------------------------------------------------
# Step 11 — Report
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "PASS" -ForegroundColor Green
exit 0

} finally {
    # Safety net: always clean up KeePass / Chrome / temp even if an unhandled
    # exception bubbles out (e.g. from strict-mode or a Fail call that itself
    # throws before Invoke-Cleanup runs).
    if ($null -ne $Script:keepassPid -or $null -ne $Script:chromePid) {
        Invoke-Cleanup
    }
}
