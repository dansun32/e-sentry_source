<#
  Build everything on Windows (what CI runs).
  Needs: .NET 8 SDK, CMake 3.16+, Visual Studio 2022 Build Tools (C++), Python 3.10+.
  Usage:  pwsh .\build.ps1 [-SkipTests] [-Package]
    -Package  also builds netmon-win.exe with PyInstaller and writes dist\netmon-win.zip
#>
param([switch]$SkipTests, [switch]$Package)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root
function Run($exe, [string[]]$a) { & $exe @a; if ($LASTEXITCODE -ne 0) { throw "$exe $($a -join ' ') failed ($LASTEXITCODE)" } }

New-Item -ItemType Directory -Force helpers | Out-Null

# 1) C# ETW helper (self-contained single file, win-x64)
if (-not $SkipTests) { Run dotnet @('test', 'helpers/netmon-etw/tests/NetmonEtw.Tests', '-c', 'Release') }
Run dotnet @('publish', 'helpers/netmon-etw/src/NetmonEtw/NetmonEtw.csproj', '-c', 'Release', '-r', 'win-x64',
             '--self-contained', 'true', '-p:PublishSingleFile=true', '-p:DebugType=none', '-o', 'build/etw')
Copy-Item build/etw/netmon-etw.exe helpers/ -Force

# 2) C++ raw/WFP helper (MSVC, static CRT)
Run cmake @('-S', 'helpers/netmon-raw', '-B', 'build/raw', '-A', 'x64')
Run cmake @('--build', 'build/raw', '--config', 'Release')
if (-not $SkipTests) { Run ctest @('--test-dir', 'build/raw', '-C', 'Release', '--output-on-failure') }
Copy-Item build/raw/Release/netmon-raw.exe helpers/ -Force

# 3) Python core tests
if (-not $SkipTests) {
    Run python @('-m', 'pip', 'install', '--quiet', 'pytest')
    Run python @('-m', 'pytest', '-q', 'tests')
}

# 4) Optional: PyInstaller one-file core + release zip
if ($Package) {
    Run python @('-m', 'pip', 'install', '--quiet', 'pyinstaller')
    Run python @('-m', 'PyInstaller', '--noconfirm', '--clean', '--onefile', '--console', '--name', 'netmon-win',
                 '--add-data', 'netmon.html;.', '--distpath', 'build/py', '--workpath', 'build/pywork', 'netmon_win.py')
    $stage = 'build/stage/netmon-win'
    Remove-Item -Recurse -Force build/stage -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force "$stage/helpers" | Out-Null
    Copy-Item build/py/netmon-win.exe, netmon_win.py, netmon.html, Start-NetmonWin.ps1, README.md $stage
    Copy-Item helpers/netmon-etw.exe, helpers/netmon-raw.exe "$stage/helpers"
    Get-ChildItem -Recurse -File $stage | Get-FileHash -Algorithm SHA256 |
        ForEach-Object { "{0}  {1}" -f $_.Hash.ToLower(), (Resolve-Path -Relative $_.Path) } | Set-Content "$stage/SHA256SUMS.txt"
    New-Item -ItemType Directory -Force dist | Out-Null
    Compress-Archive -Path $stage -DestinationPath dist/netmon-win.zip -Force
    Write-Host "dist/netmon-win.zip written"
}
