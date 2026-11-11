# systemd-netmon 2.0

Live per-service network accounting (systemd `IPAccounting`) plus raw/packet socket
monitoring, with **guarded** stop / start / restart / kill / disable / enable / mask /
unmask actions. Web UI (default) or curses TUI (`--tui`). Python stdlib only.

Target: Linux Mint 21.3 (Ubuntu 22.04 base, systemd 249, Python 3.10). Works on any
systemd distro with Python >= 3.8.

## Quick start

```bash
mkdir -p ~/systemd-netmon
tar -xzf ~/Downloads/systemd-netmon.tgz -C ~/systemd-netmon --strip-components=1
cd ~/systemd-netmon

python3 netmon.py --read-only        # 1. look around: no root, no actions
sudo python3 netmon.py --dry-run     # 2. full data, actions only LOGGED (shows exact commands)
sudo python3 netmon.py               # 3. live actions
sudo python3 netmon.py --tui         # same thing in the terminal
```

The server prints a **launch URL** such as `http://127.0.0.1:8787/?k=XXXX`. Open that
exact URL (the key creates a browser session; the page then strips it from the address bar).
Opening plain `http://127.0.0.1:8787/` without a session shows "session required".

To see traffic numbers for a service, enable accounting for it (row menu ->
*Enable IPAccounting (runtime)*, or see "IPAccounting" below).

## Flags

| flag | meaning |
|---|---|
| `--port N` | web port (default 8787, env `NETMON_PORT`) |
| `--bind 127.0.0.1\|::1` | loopback only; anything else is refused |
| `--tui` | curses TUI instead of the web server |
| `--interval S` | TUI refresh seconds (default 1.0; `+`/`-` in the TUI) |
| `--dry-run` | actions are validated + audit-logged with the exact command, never executed |
| `--read-only` | all actions disabled (menus show "read-only") |
| `--audit-log PATH\|none` | default `/var/log/systemd-netmon/audit.log` (root) or `~/.local/state/systemd-netmon/audit.log` |
| `--deny 'GLOB'` | extra protected units, repeatable, e.g. `--deny 'docker*.service'` |
| `--self-unit NAME` | this backend's unit name (auto-detected from its cgroup) |
| `--url-file PATH` / `--url-file-owner USER` | also write the launch URL to a 0600 file (for the systemd service) |

## What you see

**Services table**: every loaded `.service` (plus masked unit files so you can unmask
them), with ActiveState/SubState, UnitFileState, rate in/out (bytes/s from deltas of
`IPIngressBytes`/`IPEgressBytes` between polls), a 60-poll sparkline, and total bytes.
View selector: *running* (default), *all services*, *IPAccounting on*.
Units without IPAccounting show **n/a**: the numbers are never invented. A counter that goes
backwards (unit restarted) shows n/a for that one poll.

**Raw / packet sockets**: `/proc/net/raw`, `/proc/net/raw6`, `/proc/net/packet`, mapped
inode -> PID -> process name -> owning unit (via `/proc/PID/cgroup`).
* **Packet rate / count is n/a**: the kernel has no per-socket packet counters for these
  sockets in /proc. What's shown instead is real: the `drops` counter (+rate) for raw
  sockets, `Rmem` bytes for packet sockets, protocol/ethertype and interface.
* Owners of other users' sockets can only be resolved as root; otherwise "unknown" and a
  banner says so.
* `/proc/net/*` is per network namespace: sockets inside containers/other netns aren't listed.

Keys (web): `Space` pause/resume, `/` filter, `R` reset totals (display baseline only),
`Esc` close. Interval 500 ms / 1 s / 2 s / 5 s. INFO drawer has reference + the active denylist.

Keys (TUI): `Tab` switch pane, arrows/PgUp/PgDn, `/` filter, `v` view, `Space` pause,
`R` reset, `+`/`-` interval, `q` quit. Services: `s` stop, `S` start, `r` restart,
`k`/`K` kill TERM/KILL, `d` disable, `e` enable, `m` mask, `u` unmask, `a` IPAccounting.
Sockets: `k`/`K` kill owning PID TERM/KILL. Every action shows the exact command and asks
`y/N`; protected targets require typing `FORCE`.

## Actions and the exact commands run

| action | command |
|---|---|
| start / stop / restart | `systemctl --no-ask-password <verb> -- UNIT` |
| kill | `systemctl --no-ask-password kill --signal=SIGTERM\|SIGKILL -- UNIT` (all processes of the unit) |
| enable / unmask | `systemctl --no-ask-password enable\|unmask -- UNIT` |
| disable / mask | `systemctl --no-ask-password disable\|mask [--now] -- UNIT` |
| IPAccounting | `systemctl --no-ask-password set-property --runtime -- UNIT IPAccounting=yes` |
| kill PID | `os.kill(PID, SIGTERM\|SIGKILL)` (shown as `kill -TERM PID`) |

No shell is ever involved (argv lists), unit names must match
`^[A-Za-z0-9_][A-Za-z0-9:_.@\\-]{0,240}\.(service|socket|timer)$`, signals are limited to
SIGTERM/SIGKILL.

Remember: `kill`/`stop` on a unit with `Restart=` may come straight back; `disable` only
affects boot (sockets/dependencies can still start it); `mask` blocks every start until
`unmask`.

## Safety model

* **Loopback only**: binds 127.0.0.1 (or ::1); other addresses refused.
* **Session + CSRF**: a random launch key (printed at start) creates an HttpOnly,
  SameSite=Strict session cookie; each session gets its own CSRF token embedded in the page
  and required (header `X-Netmon-Token`) on every POST. Other local users/processes can't
  just fetch the page to obtain a token. All keys rotate on restart.
* **Host header check** (DNS-rebinding defence) on every request; **Origin check** on POST;
  POST must be `application/json` (no simple cross-site forms), body <= 4 KB.
* `Content-Security-Policy: default-src 'none'; script-src 'self' ...`, `X-Frame-Options: DENY`,
  all dynamic text HTML-escaped (process names are attacker-controlled).
* **Denylist** (destructive actions stop/restart/kill/disable/mask refused unless `force`):
  systemd-journald, dbus/dbus-broker, systemd-logind, systemd-udevd, NetworkManager,
  systemd-networkd, systemd-resolved, lightdm/gdm/gdm3/sddm/display-manager, polkit,
  **piavpn.service**, **ufw.service**, **netfilter-persistent.service**, `user@*.service`,
  this backend (`systemd-netmon.service` + auto-detected own unit), and `ssh`/`sshd` while an
  SSH session is active. Add more with `--deny`. Start/enable/unmask/IPAccounting are always allowed.
  The UI's override = typing the unit name (or the PID); the TUI's = typing `FORCE`.
* **PID kills**: refuse PID <= 1, the backend and its parent (e.g. sudo), kernel threads;
  require the socket inode and re-verify the PID still owns it (guards against PID reuse);
  PIDs whose cgroup unit is on the denylist need force.
* **Audit log**: JSON lines (mode 0600) for every attempt: refused, invalid, dry-run, ok,
  error, with client, exact argv, rc and stderr.
* `--dry-run` and `--read-only` as above.

## Root, sudo, or polkit

* Simplest: `sudo python3 netmon.py`. Needed for PID kills of other users' processes and
  for complete socket-owner mapping.
* Without sudo: install the polkit rule so user `dan` can manage units without a password
  (active local session only). **Mint 21.3 has polkit 0.105 -> use the `.pkla` file**:
  ```bash
  sudo cp packaging/50-systemd-netmon.pkla /etc/polkit-1/localauthority/50-local.d/
  python3 netmon.py
  ```
  (`packaging/50-systemd-netmon.rules` is the JavaScript equivalent for polkit >= 0.106.)
  Trade-off: any process running as dan gets the same unit-control power. Delete the file to revoke.

## Run it as a systemd service

```bash
sudo mkdir -p /opt/systemd-netmon
sudo cp -r ~/systemd-netmon/. /opt/systemd-netmon/
sudo cp /opt/systemd-netmon/packaging/systemd-netmon.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now systemd-netmon.service
cat /run/systemd-netmon/launch-url        # readable by dan only; open this URL
```
The shipped unit passes `--dry-run`; edit `ExecStart` to remove it once you're happy,
then `sudo systemctl daemon-reload && sudo systemctl restart systemd-netmon`.
The backend refuses to stop/kill/mask its own unit unless forced.

## IPAccounting

Counters only exist for units with `IPAccounting=yes` (eBPF on the unit's cgroup, cgroup v2,
which Mint 21.3 uses by default). Counting starts when it's enabled.
```bash
sudo systemctl set-property --runtime cups.service IPAccounting=yes   # until reboot (what the UI does)
sudo systemctl set-property cups.service IPAccounting=yes             # persistent drop-in
# every service: set DefaultIPAccounting=yes in /etc/systemd/system.conf, then
sudo systemctl daemon-reexec   # and restart the services you care about
```
Traffic of processes outside services (your browser, apps in `user@1000.service` / session
scopes) isn't attributed to a system service.

## Firewall / VPN notes

* The page loads **nothing from the internet**: Tailwind is precompiled into
  `static/app.css`, the few Lucide icons are vendored in `static/icons.js`, fonts are local
  (JetBrains Mono if installed, else DejaVu Sans Mono). Your DROP-by-default raw table / PIA
  killswitch can't break it, **as long as loopback is allowed**. If the page won't load:
  `sudo iptables -t raw -S | grep -- '-i lo\|-o lo'`. You need ACCEPT rules for `lo` in
  PREROUTING/OUTPUT (and in filter INPUT/OUTPUT).
* piavpn, ufw and netfilter-persistent are protected because stopping them can open or kill
  your network path.

## Tests

```bash
sudo apt install python3-pytest     # or: pip install pytest
cd ~/systemd-netmon && python3 -m pytest -q
```
Offline only: /proc fixtures, `systemctl show` parsing, rate maths, validation, denylist,
dry-run/read-only, PID-kill guards, CSRF/Origin/Host/session checks against a real
in-process server with a fake runner. Nothing touches systemd or sends signals.

## Layout

```
netmon.py                 CLI entry (web server / --tui)
netmonlib/systemd.py      systemctl list/show parsing + rate sampler
netmonlib/procnet.py      /proc/net/{raw,raw6,packet} parsers, inode->PID->unit mapping
netmonlib/actions.py      validation, command building, denylist, executor, audit log
netmonlib/server.py       http.server app: session/CSRF, JSON API, static files
netmonlib/tui.py          curses TUI
static/                   index.html, app.js, app.css (compiled Tailwind), base.css, icons.js
packaging/                systemd unit, polkit .pkla (Mint 21) and .rules (polkit >= 0.106)
tests/                    pytest suite + fixtures
tools/                    dev-only: rebuild icons.js / app.css (needs node; not needed to run)
```

### API (for scripting)
`GET /api/config`, `GET /api/snapshot` (session cookie), `POST /api/unit/preview`,
`/api/unit/action` `{unit, action, signal?, now?, force?}`, `/api/pid/preview`,
`/api/pid/kill` `{pid, inode, signal, force?}` (cookie + `X-Netmon-Token` + JSON).

### Why `systemctl` instead of D-Bus bindings
Zero pip dependencies (dbus-python/dbus-next/pydbus are not needed), identical behaviour
to what you'd type yourself (so the confirmation dialog shows a command you can paste),
polkit works unchanged, and one `systemctl show -p ... unit1 unit2 ...` call fetches all
properties for ~120 units per process spawn. Under the hood systemctl still uses
`org.freedesktop.systemd1` over D-Bus.

Mockup fix carried over: after RESUME the button now reads **PAUSE** (it used to say "PAUSED").
