# Windows downloads

Fetch only this folder (Git for Windows, PowerShell or cmd):

```
git clone --depth 1 --filter=blob:none --sparse https://github.com/dansun32/e-sentry_source
cd e-sentry_source
git sparse-checkout set windows
cd windows
```

Needs Python 3.10+ (`winget install -e --id Python.Python.3.12`). The helpers in `helpers/` are prebuilt, self-contained 64-bit executables; no .NET or C++ runtime is needed.

Run (asks for admin, opens http://127.0.0.1:8787/):

```
powershell -ExecutionPolicy Bypass -File .\Start-NetmonWin.ps1
```

The executables are unsigned, so SmartScreen or antivirus may warn. Check them against `SHA256SUMS.txt`. Source and build scripts are in `netmon-win/` at the repo root.
