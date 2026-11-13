<#
  Start the netmon-win helper elevated and open the hosted dashboard (https://e-sentry.net/),
  which reads live data from the helper on http://127.0.0.1:PORT/api/data.  Read-only; nothing is changed.
  Usage:  powershell -ExecutionPolicy Bypass -File .\Start-NetmonWin.ps1 [-Port 8787] [-Handles] [-NoElevate] [-Local] [-NoBrowser]
    -Local      open the copy served by the helper (http://127.0.0.1:PORT/) instead of e-sentry.net
    -NoBrowser  do not open a browser
#>
param([int]$Port = 8787, [switch]$Handles, [switch]$NoElevate, [switch]$Local, [switch]$NoBrowser)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$admin = ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin -and -not $NoElevate) {
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-NoExit', '-File', "`"$PSCommandPath`"", '-Port', $Port)
    if ($Handles) { $argList += '-Handles' }
    if ($Local) { $argList += '-Local' }
    if ($NoBrowser) { $argList += '-NoBrowser' }
    Start-Process powershell -Verb RunAs -ArgumentList $argList   # UAC prompt
    return
}
$extra = @('--port', $Port)
if ($Local) { $extra += '--open-local' } elseif (-not $NoBrowser) { $extra += '--open' }
if ($Port -ne 8787 -and -not $Local) { Write-Host "Non-default port: open https://dansun32.github.io/e-sentry_source/?helper=$Port" }
if ($Handles) { $extra += '--handles' }
$exe = Join-Path $here 'netmon-win.exe'
$script = Join-Path $here 'netmon_win.py'
if (Test-Path $exe) { & $exe @extra }
elseif (Get-Command py -ErrorAction SilentlyContinue) { & py -3 $script @extra }
elseif (Get-Command python -ErrorAction SilentlyContinue) { & python $script @extra }
else { Write-Error 'Neither netmon-win.exe nor Python 3 was found. Install Python 3.10+ from python.org.' }
