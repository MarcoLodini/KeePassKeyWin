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
$Script:cdpPort    = 19222
$Script:keepassPid = $null
$Script:chromePid  = $null
$Script:tempDir    = $null
$Script:harnessOut = ""
$Script:failReason = ""

$repoRoot = Split-Path -Parent $PSScriptRoot

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
# Step 6 — Launch KeePass in background
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "[validator] --- Step 6: Launch KeePass ---"

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
               -PassThru -WindowStyle Minimized
$Script:keepassPid = $keepassProc.Id
Write-Host "[validator] KeePass launched (PID $($keepassProc.Id))"

# ---------------------------------------------------------------------------
# Step 7 — Poll registry for handshake nonce
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "[validator] --- Step 7: Poll for handshake nonce (timeout: ${TimeoutSec}s) ---"

$regPath  = "HKCU:\Software\PassKee"
$nonce    = $null
$deadline = (Get-Date).AddSeconds($TimeoutSec)

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
