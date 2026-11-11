#!/usr/bin/env python3
"""systemd-netmon: live per-unit IP accounting + raw/packet socket monitor with
guarded stop/kill/disable/mask actions.  Web UI by default, curses TUI with --tui.

    sudo python3 netmon.py                 # web UI on http://127.0.0.1:8787 (launch URL printed)
    sudo python3 netmon.py --tui           # terminal UI
    python3 netmon.py --read-only          # no actions, no root needed (partial socket owners)
    sudo python3 netmon.py --dry-run       # actions are logged, never executed
"""
from __future__ import annotations

import argparse
import os
import pwd
import secrets
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from netmonlib import __version__  # noqa: E402
from netmonlib.actions import AuditLog, Executor, Policy, detect_self_unit  # noqa: E402
from netmonlib.systemd import Sampler  # noqa: E402


def default_audit_path() -> str:
    if os.geteuid() == 0:
        return "/var/log/systemd-netmon/audit.log"
    base = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
    return os.path.join(base, "systemd-netmon", "audit.log")


def write_url_file(path: str, url: str, owner: str | None):
    uid = gid = None
    if owner:
        uid, gid = pwd.getpwnam(owner).pw_uid, pwd.getpwnam(owner).pw_gid
    elif os.environ.get("SUDO_UID"):
        uid, gid = int(os.environ["SUDO_UID"]), int(os.environ.get("SUDO_GID", "0"))
    chown = uid is not None and os.geteuid() == 0
    d = os.path.dirname(path)
    if d and not os.path.isdir(d):
        os.makedirs(d, mode=0o700)
        if chown:
            os.chown(d, uid, gid)
    if os.path.lexists(path):
        os.unlink(path)  # never follow a pre-planted symlink
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(url + "\n")
    if chown:
        os.chown(path, uid, gid)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="netmon.py", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=int(os.environ.get("NETMON_PORT", 8787)),
                    help="web UI port (default 8787, env NETMON_PORT)")
    ap.add_argument("--bind", default="127.0.0.1", choices=["127.0.0.1", "::1"],
                    help="loopback address to bind (non-loopback is refused)")
    ap.add_argument("--tui", action="store_true", help="run the curses terminal UI instead of the web server")
    ap.add_argument("--interval", type=float, default=1.0, help="TUI refresh seconds (default 1.0)")
    ap.add_argument("--dry-run", action="store_true", help="log actions (and exact commands) without executing")
    ap.add_argument("--read-only", action="store_true", help="disable all actions")
    ap.add_argument("--audit-log", default=None,
                    help="audit log path (default /var/log/systemd-netmon/audit.log as root, "
                         "else ~/.local/state/systemd-netmon/audit.log); 'none' disables")
    ap.add_argument("--deny", action="append", default=[], metavar="PATTERN",
                    help="extra protected unit glob (repeatable), e.g. --deny 'docker*.service'")
    ap.add_argument("--self-unit", default=None, help="unit name of this backend (auto-detected)")
    ap.add_argument("--url-file", default=None,
                    help="also write the launch URL (contains the session key) to this file, mode 0600")
    ap.add_argument("--url-file-owner", default=None, help="chown --url-file to this user (default: $SUDO_USER)")
    ap.add_argument("--launch-key", default=os.environ.get("NETMON_LAUNCH_KEY"),
                    help=argparse.SUPPRESS)  # fixed key for tests/automation (env NETMON_LAUNCH_KEY)
    ap.add_argument("--version", action="version", version="systemd-netmon " + __version__)
    a = ap.parse_args(argv)

    audit_path = None if (a.audit_log or "").lower() == "none" else (a.audit_log or default_audit_path())
    audit = AuditLog(audit_path)
    sampler = Sampler()
    policy = Policy(extra=a.deny, self_unit=a.self_unit or detect_self_unit())
    executor = Executor(policy, audit, dry_run=a.dry_run, read_only=a.read_only,
                        on_change=sampler.invalidate)

    if not sampler.have_systemd:
        print("WARNING: systemd is not running as init here (/run/systemd/system missing); "
              "service data will be empty, raw sockets still work.", file=sys.stderr)
    if os.geteuid() != 0 and not a.read_only:
        print("NOTE: not root. Socket owners of other users' processes can't be resolved and unit "
              "actions need sudo or the polkit rule (see README). Use --read-only to hide actions.",
              file=sys.stderr)

    if a.tui:
        from netmonlib.tui import TUI
        TUI(sampler, executor, a.interval).run()
        return 0

    from netmonlib.server import App, make_server
    app = App(sampler, executor, a.port, a.launch_key or secrets.token_urlsafe(24))
    srv = make_server(app, a.bind, a.port)
    host = "[::1]" if a.bind == "::1" else "127.0.0.1"
    url = "http://%s:%d/?k=%s" % (host, srv.server_address[1], app.sessions.launch_key)
    mode = "READ-ONLY" if a.read_only else ("DRY-RUN" if a.dry_run else "LIVE ACTIONS")
    print("systemd-netmon %s  mode=%s  audit=%s" % (__version__, mode, audit_path or "disabled"), flush=True)
    print("Open: %s" % url, flush=True)
    if a.url_file:
        write_url_file(a.url_file, url, a.url_file_owner)
        print("Launch URL also written to %s" % a.url_file, flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
