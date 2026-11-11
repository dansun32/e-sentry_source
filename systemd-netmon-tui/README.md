# systemd-netmon-tui 3.0.0

Terminal-only edition of systemd-netmon: live per-service network accounting (systemd
`IPAccounting`) plus raw/packet sockets, with guarded stop / start / restart / kill /
disable / enable / mask / unmask actions. **Pure Python 3 standard library (curses).**
No web server, no HTML/JS, no pip packages. It **maximises its own terminal window** on start.

Target: Linux Mint 21.3 Cinnamon (Ubuntu 22.04 base, systemd 249, Python 3.10).

## Install

```bash
mkdir -p ~/systemd-netmon-tui
tar -xzf ~/.grok_exports/systemd-netmon-tui.tgz -C ~/systemd-netmon-tui --strip-components=1
cd ~/systemd-netmon-tui
sudo apt install wmctrl xdotool        # optional but recommended: in-place maximising
sh packaging/install-desktop.sh        # optional: menu launcher "systemd-netmon (TUI)"
```

## Run

```bash
python3 netmon_tui.py --read-only        # look around: no root, no actions
sudo python3 netmon_tui.py --dry-run     # full data; actions are only logged (exact commands)
sudo python3 netmon_tui.py               # live actions
python3 netmon_tui.py --sudo             # maximise as you, THEN sudo in the same window
python3 netmon_tui.py --spawn --sudo     # open a NEW maximised gnome-terminal, password prompt inside it
```
Menu launcher (after `install-desktop.sh`): *systemd-netmon (TUI)*. Right-click it for
*dry-run* or *read-only*.

## How it maximises itself

1. **Not on a terminal** (started from the menu/launcher) **or `--spawn`**: it re-launches
   itself in a terminal emulator using that terminal's own maximise flag. It picks a terminal
   from `--terminal`, then `$NETMON_TERMINAL`, then your desktop (Cinnamon/GNOME → gnome-terminal,
   XFCE → xfce4-terminal, MATE → mate-terminal, KDE → konsole), then whatever is installed:

   | terminal | command |
   |---|---|
   | gnome-terminal | `gnome-terminal --maximize -- python3 netmon_tui.py ...` |
   | xfce4-terminal | `xfce4-terminal --maximize -x ...` |
   | mate-terminal | `mate-terminal --maximize -x ...` |
   | tilix | `tilix --maximize -e '...'` |
   | konsole | `konsole -e ...`, then step 2 maximises it (konsole has no --maximize) |
   | kitty | `kitty --start-as=maximized ...` |
   | xterm | `xterm -maximized -e ...` |
   | x-terminal-emulator | `x-terminal-emulator -e ...`, then step 2 |

   The new window runs with `--hold`, so an error or a wrong sudo password leaves the window
   open with a message. It won't open a GUI terminal as root: use `--sudo` instead of `sudo`.
2. **Already in a terminal**: it asks the window manager, stopping at the first method that
   works. It checks with `xprop _NET_WM_STATE`, or by watching the terminal grow.
   1. `wmctrl -i -r $WINDOWID -b add,maximized_vert,maximized_horz` (when the terminal sets `WINDOWID`)
   2. `wmctrl -r :ACTIVE: -b add,maximized_vert,maximized_horz`
   3. `xdotool windowstate --add MAXIMIZED_VERT,MAXIMIZED_HORZ` (needs xdotool 2021+; Mint 21's
      3.20160805 doesn't have it), then `xdotool ... windowmove 0 0 windowsize 100% 100%`
   4. The xterm window-op escape `CSI 9;1t`. Real xterm honours it; VTE terminals
      (gnome-terminal, xfce4, mate, tilix) ignore it, so it is skipped when `VTE_VERSION` is set.
   5. Wayland: it can't maximise in place; it prints a warning (`--spawn` still works).

   **sudo**: `sudo` usually strips `DISPLAY`/`XAUTHORITY`/`WINDOWID`. When it runs as root
   it reads them back from the parent shell's `/proc/PID/environ` (falling back to
   `~$SUDO_USER/.Xauthority`). Simpler still: use `--sudo`, which maximises as you and only
   then runs `sudo`.
3. `--no-maximize` skips all of this. `--maximise-only` runs just the maximise step and prints
   what happened (handy for checking which method works on your machine).
   On exit, only the terminal state is restored. The window stays maximised.

If the window is smaller than 80x20 it shows a "terminal too small" message instead of the UI.
Resizing is handled live.

## Screen

Header bar: version, LIVE/PAUSED, mode badge (`[DRY-RUN]`, `[READ-ONLY]`,
`[ACTIONS ARMED root]`), OS and kernel (from `/etc/os-release` + `uname`), view, interval,
host. Summary bar: total ingress/egress, running/loaded units (with IPAccounting), socket
count. Top pane: services sorted by throughput: state (`active/running enabled`, masked in
red), `[KBPS]`, in/out, a Unicode sparkline (shared scale across rows, so bars compare), and
total. Protected units are marked `!`. Bottom pane: raw/packet sockets with inode, process,
PID, protocol/ethertype, iface, drops/Rmem, owning unit. Then a status line and the key bar.
Colours: 256-colour cyan/green/amber like the mockup; 8-colour fallback; monochrome
(bold/reverse/dim) if `NO_COLOR` is set or the terminal has no colours. Unicode box/blocks
fall back to ASCII on non-UTF-8 locales. `--color auto|256|8|mono` overrides.

## Keys

| key | action |
|---|---|
| Space | pause / resume |
| / | filter (Enter keep, Esc clear) |
| r | reset totals + sparklines (display only; kernel counters untouched) |
| + / - , 1 2 3 | slower / faster, or 0.5 s / 1 s / 2 s |
| Tab | switch pane |
| ↑ ↓ j k PgUp PgDn Home End | select |
| Enter or a | action menu for the selected row |
| d | details / info drawer (all fields, reference, denylist, mode, audit log path) |
| v | view: running / all services / IPAccounting on |
| ? | help |
| q | quit (Esc closes overlays) |

Action menu hotkeys (units): `S` start, `s` stop, `r` restart, `t` kill SIGTERM, `k` kill
SIGKILL, `e` enable, `D` disable, `m` mask, `u` unmask, `i` enable IPAccounting (runtime).
Sockets: `t`/`k` kill owning PID with TERM/KILL, `s` stop the owning service.

Every action opens a confirm dialog showing the **exact command**. Kill and mask are red,
stop/restart/disable amber. For disable/mask, Space toggles `--now`. Enter/y runs it,
Esc/n cancels. **Protected units need the unit name typed** (a PID needs the PID typed).

## Actions and safety (same code as the proven 2.0.0 backend)

* Commands are argv lists, never a shell: `systemctl --no-ask-password <verb> -- UNIT`,
  `kill --signal=SIGTERM|SIGKILL`, `disable|mask [--now]`,
  `set-property --runtime -- UNIT IPAccounting=yes`. PID kill = `os.kill()` (shown as `kill -TERM PID`).
* Unit names must match `^[A-Za-z0-9_][A-Za-z0-9:_.@\\-]{0,240}\.(service|socket|timer)$`.
* Protected (stop/restart/kill/disable/mask only): journald, dbus/dbus-broker, logind, udevd,
  NetworkManager, networkd, resolved, lightdm/gdm/sddm/display-manager, polkit,
  **piavpn**, **ufw**, **netfilter-persistent**, `user@*.service`, systemd-netmon(-tui) units,
  ssh/sshd while an SSH session is active, plus anything from `--deny GLOB`.
* PID kills refuse PID ≤ 1, itself and its parent, and kernel threads. They require the socket
  inode and re-check that the PID still owns it (PID-reuse guard). PIDs of protected units need the override.
* Audit log (JSON lines, 0600) of every attempt, including refusals and dry-runs:
  `/var/log/systemd-netmon/tui-audit.log` as root, else `~/.local/state/systemd-netmon/tui-audit.log`
  (`--audit-log PATH|none`).
* `--dry-run`: validated + logged, never executed. `--read-only`: no actions at all.

### Without sudo: polkit
Mint 21.3 ships polkit 0.105, so it uses the `.pkla` file (not the `.rules` file):
```bash
sudo cp packaging/50-systemd-netmon.pkla /etc/polkit-1/localauthority/50-local.d/
```
This lets `dan` manage units passwordless from an active local session, and so does any
process running as dan. Killing other users' PIDs and seeing all socket owners still need root.

## Data honesty / limitations

* Rates only exist for units with `IPAccounting=yes`; others show **n/a**. Enable per unit
  from the menu (`i`, runtime), persistently with `sudo systemctl set-property UNIT IPAccounting=yes`,
  or for every service with `DefaultIPAccounting=yes` in `/etc/systemd/system.conf`.
* The kernel has no per-socket packet counters for raw/packet sockets: PKTS/S is always
  n/a. Drops (raw) and Rmem (packet) are real.
* Only the current network namespace is shown. Socket owners of other users need root.
* `kill`/`stop` on units with `Restart=` may respawn. `disable` only affects boot.

## Tests

```bash
sudo apt install python3-pytest      # pyte optional: pip install pyte (enables the real-pty curses test)
cd ~/systemd-netmon-tui && python3 -m pytest -q
```
Offline only: parsers (/proc fixtures, `systemctl show`), rates, validation, denylist,
dry-run/read-only, PID guards, terminal/maximise command selection, sudo env recovery, the
curses UI drawn on a fake screen (layout, sorting, filter, views, menus, confirm, protected
override, drawer, resize, too-small), and, if `pyte` is installed, the real curses app under a
pseudo-terminal including a resize. `tests/fakehost.py` runs the UI against a stub systemctl
and fake /proc (dry-run) if you want to try it without touching your system.

## Layout

```
netmon_tui.py              entry: spawn / maximise / --sudo / UI
netmontui/ui.py            curses UI (theme, panes, overlays, keys, poller thread)
netmontui/maximise.py      terminal spawn + in-place maximise + sudo env recovery
netmontui/fmt.py           formatting, sparkline, column layout (pure)
netmontui/systemd.py       systemctl list/show parsing + rate sampler
netmontui/procnet.py       /proc/net/{raw,raw6,packet} + inode -> PID -> unit
netmontui/actions.py       validation, command building, denylist, executor, audit log
packaging/                 .desktop template + installer, polkit .pkla / .rules
tests/                     pytest suite, fixtures, fake host, pty helper
```
