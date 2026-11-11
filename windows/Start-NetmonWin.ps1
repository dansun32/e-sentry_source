<#
  Start netmon-win elevated and open the page.  Read-only monitor; nothing is changed on the system.
  Usage:  powershell -ExecutionPolicy Bypass -File .\Start-NetmonWin.ps1 [-Port 8787] [-Handles] [-NoElevate]
#>
param([int]$Port = 8787, [switch]$Handles, [switch]$NoElevate)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$admin = ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin -and -not $NoElevate) {
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-NoExit', '-File', "`"$PSCommandPath`"", '-Port', $Port)
    if ($Handles) { $argList += '-Handles' }
    Start-Process powershell -Verb RunAs -ArgumentList $argList   # UAC prompt
    return
}
$extra = @('--port', $Port, '--open')
if ($Handles) { $extra += '--handles' }
$exe = Join-Path $here 'netmon-win.exe'
$script = Join-Path $here 'netmon_win.py'
if (Test-Path $exe) { & $exe @extra }
elseif (Get-Command py -ErrorAction SilentlyContinue) { & py -3 $script @extra }
elseif (Get-Command python -ErrorAction SilentlyContinue) { & python $script @extra }
else { Write-Error 'Neither netmon-win.exe nor Python 3 was found. Install Python 3.10+ from python.org.' }
