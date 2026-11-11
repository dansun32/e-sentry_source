# win_port.md: systemd-netmon-live as a Windows app

## Overview

The page stays the same and gets a new Windows back end: one helper per job, with a thin Python core that polls the helpers and serves the page.

## Per-service traffic: C# helper

- Uses the `Microsoft.Diagnostics.Tracing.TraceEvent` library to subscribe to ETW (Event Tracing for Windows) kernel TCP/IP events, which give real per-process bytes in and out. This is the same source Resource Monitor uses.
- Maps each PID to its services through the service control manager. This matters because many services share one `svchost.exe`.
- Writes totals per service as JSON lines to the Python core over a local pipe.
- Needs admin rights. Published as a single self-contained `.exe`.
- Service list, state, start type, and optional stop or disable also live here, through `ServiceController`.

## Raw sockets panel: C++ helps, Perl doesn't

Windows doesn't list raw sockets anywhere public. The IP Helper tables (`GetExtendedTcpTable` / `GetExtendedUdpTable`) only cover TCP and UDP. On Windows the panel becomes "who can see or inject packets below the normal stack", and the real sources are native:

- **Packet capture drivers.** Enumerate Npcap or WinPcap adapters and find which processes have the capture driver open. This needs native handle inspection (`NtQuerySystemInformation`), which C++ does cleanly.
- **Raw socket owners.** Found through ETW Winsock events (raw socket creation) or handle inspection of `\Device\Afd` endpoints. Native code is the natural fit.
- **WFP (Windows Filtering Platform).** Through the `Fwpm*` APIs, list the filters and callouts registered by VPNs or other tools. This is the closest Windows equivalent of the "bypassing hosts.deny" angle, and it would show PIA's killswitch rules too.

**Perl** adds nothing here. On Windows it would just wrap the same APIs through Win32 modules, with less support than Python or C++.

**Alternative:** C# could also do the WFP and handle work via P/Invoke, giving a single helper with no separate C++ build. C++ is the better choice for the lowest overhead and the most direct access to undocumented handle details.

## Suggested split

| Component | Language | Role |
|---|---|---|
| `netmon-etw.exe` | C# | Service traffic, service state and actions |
| `netmon-raw.exe` | C++ | Capture drivers, raw socket owners, WFP filters |
| Python core | Python | Polls both helpers and serves the original page relabelled for Windows; packaged with PyInstaller |

## Caveats

- Everything needs admin rights.
- Antivirus may flag handle inspection and ETW kernel sessions.
- Development can only be built and tested against fake data. Compiling happens in CI or on a Windows machine, which would also be its first real test.

## Order of work

Build the C# helper first, since it gets the most visible result fastest. Then add the C++ helper.
