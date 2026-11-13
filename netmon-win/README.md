# netmon-win: the systemd-netmon live page, ported to Windows

This is the same page as `systemd-netmon-live`: same layout, Tailwind/Lucide/JetBrains Mono CDN
links, header, summary bar, two panels, footer, drawer and keys (Space / `/` / R). It now has a
Windows back end. It is **read-only**: nothing is stopped, disabled or changed.

| Piece | Language | What it does |
|---|---|---|
| `helpers/netmon-etw.exe` | C# (.NET 8, self-contained single file, win-x64) | Opens a private ETW kernel session (`NetworkTCPIP` + `Process`) and sums TcpIp/UdpIp Send/Recv bytes per PID. Maps each PID to services through the SCM (`EnumServicesStatusEx`, `QueryServiceConfig`). Prints one JSON line per interval (`netmon-etw/1`) on stdout, or on `--pipe NAME`. |
| `helpers/netmon-raw.exe` | C++17 (CMake; MSVC or mingw-w64) | Reports Npcap/WinPcap install state, processes that loaded `wpcap.dll`/`Packet.dll`, and an optional handle scan. Summarises WFP filters and callouts (`FwpmFilterEnum0` / `FwpmCalloutEnum0`) by provider, layer and action. Prints one JSON object (`netmon-raw/1`). |
| `netmon_win.py` | Python 3.10+, stdlib only | Runs both helpers, computes rates and serves `netmon.html` and `/api/data` on **127.0.0.1:8787**. If a helper is missing it falls back to `sc queryex`, `tasklist /svc` and `netstat -ano`. |

## Requirements

* Windows 10 or 11, x64.
* **Administrator** rights for ETW bytes and the WFP summary. Without them the page still runs and
  shows the service list plus connection counts, with an amber banner explaining what is missing.
* .NET runtime: **not needed**, because `netmon-etw.exe` is self-contained (about 36 MB).
* VC++ runtime: **not needed**. `netmon-raw.exe` links its C++ runtime statically and uses the UCRT
  that ships with Windows 10/11.
* Python 3.10+ from python.org, *or* the PyInstaller-built `netmon-win.exe` from CI (see Build).
* Npcap: optional. Without it the capture rows are simply empty.
* Browser access to `cdn.tailwindcss.com`, `unpkg.com` and `fonts.googleapis.com`. If they are
  blocked (for example by a VPN killswitch), the page still works with live data but is unstyled.

## Run

The page is hosted on GitHub at **https://e-sentry.net/**; the helper feeds it live data from
`http://127.0.0.1:8787/api/data`. Chrome may ask to allow the site to access devices on your local
network: click **Allow**.

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

`Start-NetmonWin.ps1` asks for elevation (UAC), starts the core and opens https://e-sentry.net/
(`-Local` opens the helper's own copy at http://127.0.0.1:PORT/ instead, `-NoBrowser` opens nothing).
By hand from an *Administrator* PowerShell: `py -3 netmon_win.py --open` (or `.\netmon-win.exe` from a CI build).
With a non-default port, open `https://dansun32.github.io/e-sentry_source/?helper=PORT`.

Options: `--allow-origin ORIGIN` (another site allowed to read `/api/data`, repeatable), `--port 8787`, `--interval 1.0` (ETW snapshot period in seconds), `--raw-period 15`
(seconds between `netmon-raw` runs), `--handles` (enable the optional handle scan), `--no-wfp`,
`--fallback` (ignore ETW; use sc, tasklist and netstat only), `--open` (opens e-sentry.net), `--open-local`, `--etw-exe PATH`,
`--raw-exe PATH`. Stop it with Ctrl-C. The ETW helper is started with `--exit-on-stdin-eof`, so it
closes its kernel session when the core exits. If a session is ever left behind, remove it with
`logman stop netmon-etw -ets`.

You can also run the helpers on their own, for example `helpers\netmon-etw.exe --once`,
`helpers\netmon-raw.exe --handles`, or `--help` on either.

## What the page shows (Windows relabels)

* **Header:** the real Windows version from the registry. ProductName says "Windows 10" on
  Windows 11, so the build number is used to correct it. The status line reads `LIVE ETW POLLING`
  (green), or in amber `LIVE · NO ETW BYTES` (not elevated) or `LIVE · FALLBACK (NO ETW)`
  (helper missing). If the core stops, it shows `HELPER UNREACHABLE` in red. A thin amber banner
  under the summary bar lists anything that is degraded.
* **Summary bar:** Services Total Ingress / Egress; ETW Monitored Services
  (`monitored / running`); Capture / Raw / WFP counts.
* **WINDOWS SERVICES (SORTED TOP-DOWN BY THROUGHPUT):** one row per service process.
  * **Attribution:** ETW reports bytes per *process*. A process that hosts a single service gives
    an exact per-service figure. When several services share one `svchost.exe`, the row is named
    `FirstService +N` and its tooltip lists all members. The bytes belong to the whole process and
    are **not split** between the services, because the kernel does not record which service sent
    them. On Windows 10 1703+ with more than 3.5 GB RAM, most services run in their own svchost.
  * **Fallback mode:** byte columns show n/a and Total Data shows the connection count from
    `netstat -ano`.
  * The filter also matches display names, member services, the process name and the PID.
* **CAPTURE / RAW / WFP PANEL (BELOW THE NORMAL STACK):** the Linux raw/packet-socket panel,
  relabelled. Columns are Kind / Process or Provider / PID / Source or Layer / Detail / Count.
  * `DRIVER`: Npcap/WinPcap service state and adapter count.
  * `CAPTURE`: processes with `wpcap.dll`/`Packet.dll` loaded. With `--handles`, also processes
    holding `\Device\NPCAP*` / `\Device\NPF_*` handles.
  * `RAW`: only legacy `\Device\RawIp*` handle holders (see Limitations).
  * `WFP`: filter groups by provider, layer and action (block, permit or callout). This is where
    PIA's killswitch rules appear. The tooltip shows sample filter names.
  * `CALLOUT`: registered callouts per provider.
  * The **WFP: ON/OFF** button or the **W** key hides or shows the WFP rows.
* **Drawer (ETW INFO):** rewritten for ETW, the attribution rule, a TraceEvent snippet and
  Npcap/WFP. The footer reads `ETW: Microsoft-Windows-Kernel-Network`.

All values are HTML-escaped in the page, and the helpers also escape `<`, `>` and `&` in their
JSON. Typing in the filter box no longer triggers the Space, R or W shortcuts.

## Security

* The core serves GET only (other methods get 405) and binds to 127.0.0.1. It returns 421 unless
  the Host header is `127.0.0.1:PORT` or `localhost:PORT`, to block DNS rebinding. CORS headers are sent only for
  `GET /api/data` (and its preflight, including `Access-Control-Allow-Private-Network`) when the
  Origin is exactly `https://dansun32.github.io`, `https://e-sentry.net`, `https://www.e-sentry.net`
  or one added with `--allow-origin`. Nothing else is ever shared cross-origin.
* `netmon-etw --pipe NAME` creates the pipe with a DACL that allows the current user only.
* No helper modifies anything. The optional handle scan duplicates handles into its own process
  only to read their names (it never closes handles in other processes). Every name query runs on
  a worker thread with a timeout (default 150 ms, `--handle-timeout-ms`), synchronous pipes are
  skipped, and the scan aborts after 5 timeouts or 20 s.

## Antivirus / SmartScreen

The binaries are **unsigned**. ETW kernel sessions, `SeDebugPrivilege` plus module enumeration and,
above all, the optional `NtQuerySystemInformation`/`NtQueryObject` handle scan are techniques that
EDR and antivirus products watch for, so expect a SmartScreen prompt and possibly a heuristic
detection. Build from source (below) if you prefer, and leave `--handles` off unless you need it.

## Build

* **CI:** `.github/workflows/build.yml` (windows-latest) runs `build.ps1 -Package`. That runs
  `dotnet test`, publishes `netmon-etw.exe`, builds `netmon-raw.exe` with MSVC and runs `ctest`,
  runs `pytest`, packages the core with PyInstaller (`netmon-win.exe`), and uploads
  `dist/netmon-win.zip`. Pushing a `v*` tag also attaches the zip to a GitHub release.
* **Windows, by hand:** install the .NET 8 SDK, VS 2022 Build Tools (C++), CMake and Python 3.10+,
  then run `pwsh .\build.ps1 [-Package]`.
* **Linux cross-build** (how the prebuilt helpers in this zip were made): `./build-cross.sh`.
  It needs the .NET 8 SDK, cmake/ninja and mingw-w64 or llvm-mingw (`MINGW_PREFIX=/opt/llvm-mingw/bin/`).
* **Tests:**
  * Python: `python -m pytest -q tests`. These run offline on any OS, using fake helper output
    and `tests/fakewin_server.py` for a browser demo.
  * C#: `dotnet test helpers/netmon-etw/tests/NetmonEtw.Tests`.
  * C++: the `ctest` target `netmon-raw-tests`.
* **Page:** `netmon.html` is generated from the live page by `page/make_win_page.py`, which only
  makes exact, checked string replacements. The full change is in `page/index.html.diff`.
  The OS label, setup modal and no-helper banner were added afterwards by hand (see the repo root `index.html` OS chooser).

## Test status (honest)

* **Nothing here has been run on real Windows yet.** Both helpers were cross-compiled on Linux
  (`dotnet publish -r win-x64`; llvm-mingw clang 64-bit with `-Wall -Wextra`, no warnings), but
  they were never executed, and Wine was not available. On real Windows, expect the first run to
  be the real test. In particular check the TraceEvent single-file extraction, the ETW session
  with a custom name (Windows 8+), and the WFP enumeration as Administrator.
* What did run:
  * C# core unit tests: attribution, counters, JSON shape and escaping, args.
  * C++ portable unit tests: JSON writer, WFP summary, device and module classification, args.
  * Python tests: parsers for sc, tasklist and netstat; rates; API shape; degradation paths;
    the real subprocess path with a fake helper (including a clean stop on stdin EOF and crash
    reporting); HTTP rules; page identity checks.
  * Headless Chrome render with fake Windows data, in full mode and degraded mode.

## Limitations

* **Raw sockets:** Windows has no public API that lists `SOCK_RAW` owners. Modern raw sockets are
  AFD endpoints that cannot be told apart from TCP/UDP sockets without undocumented IOCTLs. The
  panel therefore shows capture-driver users and WFP instead, plus legacy `\Device\RawIp*`
  holders if `--handles` finds any (rare on Windows 10/11).
* ETW counts payload bytes that TCP/IP attributes to a PID. Loopback and some offloaded traffic
  can be counted differently from what Resource Monitor shows. Events dropped under heavy load
  appear as `etw.eventsLost` in the helper JSON.
* Shared svchost rows are per process, not per service (see Attribution).
* Rates start after two samples. A restarted service (new PID) gets a new row, and its history
  starts empty.
* Fallback mode has no byte counts (only connection counts), and the start type is "unknown".
* WFP enumeration and the module scan need Administrator. Protected processes (PPL, for example
  antivirus) cannot be inspected and are counted as `inaccessible`.
* Npcap adapter listing loads Npcap's `wpcap.dll` into `netmon-raw` (after the scans, and the
  scan excludes its own process). Use `--no-adapters` on the helper to avoid this.
* The page still uses the internet CDNs, exactly like the original.
