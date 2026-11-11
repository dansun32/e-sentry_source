#!/usr/bin/env python3
"""systemd-netmon-tui: maximised-terminal monitor of per-service IP accounting and
raw/packet sockets, with guarded stop/kill/disable/mask actions. Pure Python stdlib (curses).

    python3 netmon_tui.py --read-only        # look around (no root)
    sudo python3 netmon_tui.py --dry-run     # actions only logged
    sudo python3 netmon_tui.py               # live actions
    python3 netmon_tui.py --spawn --sudo     # open a NEW maximised terminal, sudo prompt inside it
"""
from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from netmontui import NAME, __version__  # noqa: E402
from netmontui import maximise  # noqa: E402

SCRIPT = os.path.abspath(__file__)
# flags consumed by the launcher stages; never forwarded to the next stage
STAGE_FLAGS = {"--spawn", "--sudo", "--no-spawn", "--hold"}


def default_audit_path() -> str:
    if os.geteuid() == 0:
        return "/var/log/systemd-netmon/tui-audit.log"
    base = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
    return os.path.join(base, "systemd-netmon", "tui-audit.log")


def build_parser():
    ap = argparse.ArgumentParser(prog="netmon_tui.py", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dry-run", action="store_true", help="log actions (with exact commands) without executing")
    ap.add_argument("--read-only", action="store_true", help="disable all actions")
    ap.add_argument("--interval", type=float, default=1.0, help="refresh seconds (default 1.0)")
    ap.add_argument("--audit-log", default=None, help="audit log path, or 'none' "
                    "(default /var/log/systemd-netmon/tui-audit.log as root, else ~/.local/state/systemd-netmon/)")
    ap.add_argument("--deny", action="append", default=[], metavar="GLOB", help="extra protected unit glob (repeatable)")
    ap.add_argument("--color", choices=["auto", "256", "8", "mono"], default="auto", help="colour mode")
    g = ap.add_argument_group("window / launch")
    g.add_argument("--no-maximize", "--no-maximise", dest="no_maximize", action="store_true",
                   help="do not try to maximise the terminal window")
    g.add_argument("--spawn", action="store_true",
                   help="open a new maximised terminal window and run there (automatic when not on a TTY)")
    g.add_argument("--no-spawn", action="store_true", help="never open a new terminal window")
    g.add_argument("--terminal", default=None, help="terminal for --spawn: " + ", ".join(maximise.DEFAULT_ORDER))
    g.add_argument("--sudo", action="store_true",
                   help="maximise as your user, then re-run under sudo (password prompt in the same window)")
    g.add_argument("--hold", action="store_true", help="on error, wait for Enter before exiting (used by --spawn)")
    g.add_argument("--maximise-only", action="store_true", help="just run the maximise step, print the report, exit")
    ap.add_argument("--version", action="version", version="%s %s" % (NAME, __version__))
    return ap


def forward_args(argv, drop=STAGE_FLAGS, add=()):
    out, skip = [], False
    for i, a in enumerate(argv):
        if skip:
            skip = False
            continue
        if a in drop:
            continue
        if a == "--terminal":
            skip = True
            continue
        if a.startswith("--terminal="):
            continue
        out.append(a)
    return out + list(add)


def hold(msg: str):
    print(msg, file=sys.stderr)
    try:
        input("\n[%s] press Enter to close this window..." % NAME)
    except (EOFError, KeyboardInterrupt):
        pass


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    a = build_parser().parse_args(argv)
    on_tty = sys.stdin.isatty() and sys.stdout.isatty()
    env = dict(os.environ)

    if a.maximise_only:  # diagnostic: maximise the controlling terminal's window, print what happened
        if os.geteuid() == 0:
            env = maximise.recover_gui_env(env)
        print("\n".join(maximise.maximise_inplace(env)) or "maximise: nothing to do")
        return 0

    # ---- stage 1: not on a terminal (desktop launcher) or --spawn -> new maximised window
    if (a.spawn or not on_tty) and not a.no_spawn:
        if os.geteuid() == 0:
            print("refusing to open a GUI terminal as root; run without sudo and add --sudo", file=sys.stderr)
            return 2
        inner = [sys.executable, SCRIPT] + forward_args(argv, add=["--no-spawn", "--hold"]
                                                         + (["--sudo"] if a.sudo else []))
        ok, msg = maximise.spawn_in_terminal(inner, env, a.terminal)
        print(msg, file=sys.stderr)
        if not ok and not on_tty:
            # last resort for launchers: show the error somewhere visible
            subprocess.call(["notify-send", NAME, msg], stderr=subprocess.DEVNULL) if maximise.shutil.which("notify-send") else None
        return 0 if ok else 2

    if not on_tty:
        print("%s needs a terminal (stdin/stdout are not a TTY)" % NAME, file=sys.stderr)
        return 2

    # ---- stage 2: maximise this terminal (as the real user if possible)
    notes = []
    if not a.no_maximize:
        if os.geteuid() == 0:
            env = maximise.recover_gui_env(env)
        notes = maximise.maximise_inplace(env)

    # ---- stage 3: --sudo -> re-run privileged in this (now maximised) window
    if a.sudo and os.geteuid() != 0:
        cmd = ["sudo", "--", sys.executable, SCRIPT] + forward_args(argv, add=["--no-spawn", "--no-maximize"])
        print("$ " + " ".join(shlex.quote(c) for c in cmd), flush=True)
        rc = subprocess.call(cmd)
        if rc != 0 and a.hold:
            hold("sudo/netmon exited with status %d" % rc)
        return rc

    # ---- stage 4: the UI
    try:
        from netmontui.actions import AuditLog, Executor, Policy, detect_self_unit
        from netmontui.systemd import Sampler
        from netmontui.ui import App
        audit_path = None if (a.audit_log or "").lower() == "none" else (a.audit_log or default_audit_path())
        sampler = Sampler(min_interval=0.2)
        executor = Executor(Policy(extra=a.deny, self_unit=detect_self_unit()), AuditLog(audit_path),
                            dry_run=a.dry_run, read_only=a.read_only, on_change=sampler.invalidate)
        if not sampler.have_systemd:
            notes.append("systemd not running as init here: service list empty")
        if os.geteuid() != 0 and not a.read_only:
            notes.append("not root: other users' socket owners hidden; actions need sudo/polkit")
        sys.stdout.write("\x1b]0;%s %s\x07" % (NAME, __version__))  # window title
        sys.stdout.flush()
        App(sampler, executor, a.interval, a.color, [n for n in notes if "OK via" not in n]).run()
        return 0
    except KeyboardInterrupt:
        return 130
    except Exception:
        if a.hold:
            hold(traceback.format_exc())
        raise


if __name__ == "__main__":
    sys.exit(main())
