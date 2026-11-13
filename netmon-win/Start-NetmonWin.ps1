<#
  Start the netmon-win helper in the background (elevated, no window) and open the hosted dashboard
  https://e-sentry.net/, which reads live data from the helper on http://127.0.0.1:PORT/api/data.
  Read-only; nothing on the system is changed.

  Usage:  powershell -ExecutionPolicy Bypass -File .\Start-NetmonWin.ps1 [-Port 8787] [-Handles] [-Stop]
                     [-Local] [-NoBrowser] [-Foreground] [-NoElevate]
    -Stop        stop the background helper
    -Local       open the copy served by the helper (http://127.0.0.1:PORT/) instead of e-sentry.net
    -NoBrowser   do not open a browser
    -Foreground  run the helper in a console window instead (Ctrl-C stops it); useful to see errors
  Log:  %LOCALAPPDATA%\e-sentry\helper.log      PID file:  %LOCALAPPDATA%\e-sentry\helper.pid
#>
param([int]$Port = 8787, [switch]$Handles, [switch]$NoElevate, [switch]$Local, [switch]$NoBrowser,
      [switch]$Stop, [switch]$Foreground, [switch]$Elevated)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$stateDir = Join-Path $env:LOCALAPPDATA 'e-sentry'
$logFile = Join-Path $stateDir 'helper.log'
$pidFile = Join-Path $stateDir 'helper.pid'
$exe = Join-Path $here 'netmon-win.exe'
$script = Join-Path $here 'netmon_win.py'
if ($Local) { $pageUrl = "http://127.0.0.1:$Port/" }
elseif ($Port -ne 8787) { $pageUrl = "https://dansun32.github.io/e-sentry_source/?helper=$Port" }
else { $pageUrl = 'https://e-sentry.net/' }
$stopCmd = 'powershell -ExecutionPolicy Bypass -File .\Start-NetmonWin.ps1 -Stop'

function Test-Helper {
    try {
        $r = Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 -Uri "http://127.0.0.1:$Port/api/data"
        return ($r.StatusCode -eq 200)
    } catch { return $false }
}

function Get-HelperProcess {
    # The PID file only counts if that PID is still a netmon-win helper (not a stale / reused PID).
    if (-not (Test-Path $pidFile)) { return $null }
    $raw = Get-Content $pidFile -ErrorAction SilentlyContinue | Select-Object -First 1
    $helperPid = 0
    if (-not [int]::TryParse("$raw".Trim(), [ref]$helperPid)) { return $null }
    $p = Get-CimInstance Win32_Process -Filter "ProcessId=$helperPid" -ErrorAction SilentlyContinue
    if ($p -and ("$($p.CommandLine)" -match 'netmon_win\.py|netmon-win\.exe')) { return $p }
    return $null
}

function Show-Failure([string]$msg) {
    Write-Host ''
    Write-Host "ERROR: $msg" -ForegroundColor Red
    if (Test-Path $logFile) {
        Write-Host "Last lines of ${logFile}:" -ForegroundColor Yellow
        Get-Content $logFile -Tail 25 | ForEach-Object { Write-Host "  $_" }
    }
    Write-Host 'To see the error live, run:  powershell -ExecutionPolicy Bypass -File .\Start-NetmonWin.ps1 -Foreground'
    Read-Host 'Press Enter to close' | Out-Null
    exit 1
}

function Find-Python {
    # Returns @{ File = <pythonw.exe or python.exe>; Hidden = $true } for Python 3.10+, or $null.
    $probe = 'import sys; print(sys.executable); print(int(sys.version_info >= (3, 10)))'
    foreach ($cand in @(@('py', '-3'), @('python'))) {
        if (-not (Get-Command $cand[0] -ErrorAction SilentlyContinue)) { continue }
        try {
            $rest = @($cand | Select-Object -Skip 1)
            $out = @(& $cand[0] @rest -c $probe 2>$null)
        } catch { continue }
        if ($out.Count -lt 2 -or -not (Test-Path "$($out[0])".Trim())) { continue }  # e.g. the Microsoft Store stub
        if ("$($out[1])".Trim() -ne '1') { continue }
        $py = "$($out[0])".Trim()
        $pyw = Join-Path (Split-Path $py) 'pythonw.exe'
        if (Test-Path $pyw) { return @{ File = $pyw } }
        return @{ File = $py }
    }
    return $null
}

function Stop-Helper {
    $p = Get-HelperProcess
    if (-not $p) {
        Remove-Item $pidFile -ErrorAction SilentlyContinue
        Write-Host 'e-sentry helper is not running.'
        return
    }
    Stop-Process -Id $p.ProcessId -Force
    for ($i = 0; $i -lt 20 -and (Get-Process -Id $p.ProcessId -ErrorAction SilentlyContinue); $i++) { Start-Sleep -Milliseconds 250 }
    Remove-Item $pidFile -ErrorAction SilentlyContinue
    Write-Host "e-sentry helper stopped (PID $($p.ProcessId))."
}

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$admin = ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# ---- not elevated: re-run this script elevated (UAC), then open the browser from this normal window
if (-not $admin -and -not $NoElevate) {
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-Port', $Port, '-Elevated')
    if ($Handles) { $argList += '-Handles' }
    if ($Local) { $argList += '-Local' }
    if ($NoBrowser) { $argList += '-NoBrowser' }
    if ($Stop) { $argList += '-Stop' }
    if ($Foreground) { $argList = @('-NoExit') + $argList }
    try {
        $p = Start-Process powershell -Verb RunAs -ArgumentList $argList -PassThru   # UAC prompt
    } catch {
        Write-Host "Administrator rights were not granted, so the helper was not started. ($($_.Exception.Message))" -ForegroundColor Red
        exit 1
    }
    if ($Foreground) { exit 0 }
    $p.WaitForExit()   # the elevated window closes by itself once the helper is up (or after you read an error)
    if ($Stop) { exit 0 }
    if (Test-Helper) {
        Write-Host "e-sentry helper running in background - open $pageUrl ; stop with: $stopCmd"
        if (-not $NoBrowser) { Start-Process $pageUrl }
        exit 0
    }
    Write-Host "The helper did not start. Log: $logFile" -ForegroundColor Red
    exit 1
}

# ---- elevated (or -NoElevate) from here on
if ($Stop) {
    try { Stop-Helper } catch { Show-Failure "could not stop the helper: $($_.Exception.Message)" }
    if ($Elevated) { Start-Sleep -Seconds 2 }
    exit 0
}

$extra = @('--port', $Port)
if ($Handles) { $extra += '--handles' }

if ($Foreground) {
    if ($Local) { $extra += '--open-local' } elseif (-not $NoBrowser -and $Port -eq 8787) { $extra += '--open' }
    if (Test-Path $exe) { & $exe @extra }
    elseif (Get-Command py -ErrorAction SilentlyContinue) { & py -3 $script @extra }
    elseif (Get-Command python -ErrorAction SilentlyContinue) { & python $script @extra }
    else { Write-Error 'Neither netmon-win.exe nor Python 3 was found. Install Python 3.10+ (winget install -e --id Python.Python.3.12).' }
    exit 0
}

# ---- background start
$running = Get-HelperProcess
if ($running -and (Test-Helper)) {
    Write-Host "e-sentry helper already running in background (PID $($running.ProcessId))."
    if (-not $Elevated -and -not $NoBrowser) { Start-Process $pageUrl }
    exit 0
}
New-Item -ItemType Directory -Force $stateDir | Out-Null
$helperArgs = $extra + @('--log-file', "`"$logFile`"", '--pidfile', "`"$pidFile`"")
if (Test-Path $exe) {
    $file = $exe; $argsOut = $helperArgs
} else {
    $py = Find-Python
    if (-not $py) { Show-Failure 'Python 3.10+ was not found. Install it with: winget install -e --id Python.Python.3.12  (then open a new PowerShell)' }
    $file = $py.File; $argsOut = @("`"$script`"") + $helperArgs
}
try {
    $proc = Start-Process -FilePath $file -ArgumentList $argsOut -WorkingDirectory $here -WindowStyle Hidden -PassThru
} catch { Show-Failure "could not start ${file}: $($_.Exception.Message)" }

# wait up to ~10 s for the helper to answer
$ok = $false
for ($i = 0; $i -lt 20; $i++) {
    Start-Sleep -Milliseconds 500
    if (Test-Helper) { $ok = $true; break }
    if ($proc.HasExited) { break }
}
if (-not $ok) {
    if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
    Show-Failure "the helper did not answer on http://127.0.0.1:$Port/ within 10 seconds."
}
Write-Host "e-sentry helper running in background (PID $($proc.Id)) - log: $logFile"
Write-Host "Stop it with: $stopCmd"
if (-not $Elevated -and -not $NoBrowser) { Start-Process $pageUrl }
exit 0
