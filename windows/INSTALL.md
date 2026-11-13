# Windows: install the local helper

The dashboard runs on GitHub at **https://e-sentry.net/**. You only install the small local helper;
it feeds live data into that page from `http://127.0.0.1:8787/api/data`. Chrome may ask to allow the
site to access devices on your local network: click **Allow**.

Run these in PowerShell:

```
winget install -e --id Python.Python.3.12
winget install -e --id Git.Git
```

Close and reopen PowerShell so `python` and `git` are on your PATH, then:

```
git clone --depth 1 --filter=blob:none --sparse https://github.com/dansun32/e-sentry_source
cd e-sentry_source
git sparse-checkout set windows
cd windows
Get-FileHash .\helpers\*.exe -Algorithm SHA256
powershell -ExecutionPolicy Bypass -File .\Start-NetmonWin.ps1
```

To update later:

```
cd e-sentry_source; git pull
```

`Start-NetmonWin.ps1` asks for admin (needed for ETW traffic bytes), starts the helper and opens
https://e-sentry.net/. Options: `-Port N`, `-Handles`, `-NoBrowser`, `-Local` (open the copy the
helper serves at http://127.0.0.1:PORT/ instead). With a non-default port, open
`https://dansun32.github.io/e-sentry_source/?helper=PORT`.

The helpers in `helpers/` are prebuilt, self-contained 64-bit executables (C# ETW and C++ raw/WFP);
no .NET or C++ runtime is needed. They are unsigned, so SmartScreen or antivirus may warn: compare
the `Get-FileHash` output with `SHA256SUMS.txt`. Source and build scripts are in `netmon-win/` at the
repo root.

The helper is read-only, listens on 127.0.0.1 only, and shares `/api/data` only with
https://dansun32.github.io, https://e-sentry.net and https://www.e-sentry.net (add more with
`--allow-origin`).
