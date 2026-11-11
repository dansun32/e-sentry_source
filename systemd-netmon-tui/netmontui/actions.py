"""Validated, audited, deny-listed actions on systemd units and socket-owning PIDs."""
from __future__ import annotations

import datetime as _dt
import fnmatch
import json
import os
import re
import signal as _signal
import threading
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from . import procnet
from .systemd import Runner, default_runner

UNIT_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9:_.@\\-]{0,240}\.(service|socket|timer)$")

UNIT_ACTIONS = ("start", "stop", "restart", "kill", "enable", "disable",
                "mask", "unmask", "ipaccounting")
# Actions that can take something down -> subject to the critical-unit denylist
DESTRUCTIVE = {"stop", "restart", "kill", "disable", "mask"}
DANGER = {"kill", "mask"}  # red styling in UIs
SIGNALS = {"SIGTERM": _signal.SIGTERM, "SIGKILL": _signal.SIGKILL}

# (fnmatch pattern, reason)
DEFAULT_DENYLIST: List[Tuple[str, str]] = [
    ("systemd-journald*.service", "system logging"),
    ("systemd-journald*.socket", "system logging"),
    ("dbus.service", "system message bus"), ("dbus.socket", "system message bus"),
    ("dbus-broker.service", "system message bus"),
    ("systemd-logind.service", "login/session manager"),
    ("systemd-udevd.service", "device manager"), ("systemd-udevd-*.socket", "device manager"),
    ("NetworkManager.service", "networking (would drop all connectivity)"),
    ("systemd-networkd.service", "networking"),
    ("systemd-resolved.service", "DNS resolver"),
    ("lightdm.service", "display manager (kills your desktop session)"),
    ("gdm.service", "display manager"), ("gdm3.service", "display manager"),
    ("sddm.service", "display manager"), ("display-manager.service", "display manager"),
    ("polkit.service", "authorization daemon"), ("polkitd.service", "authorization daemon"),
    ("piavpn.service", "PIA VPN daemon (killswitch / tunnel)"),
    ("ufw.service", "firewall (stopping it removes rules)"),
    ("netfilter-persistent.service", "firewall rules loader"),
    ("user@*.service", "your user session manager"),
    ("systemd-netmon.service", "netmon web backend"),
    ("systemd-netmon-tui*.service", "this tool"),
]
SSH_UNITS = ("ssh.service", "sshd.service")


def validate_unit(unit) -> bool:
    return isinstance(unit, str) and bool(UNIT_RE.fullmatch(unit))


def build_unit_command(action: str, unit: str, sig: Optional[str] = None,
                       now: bool = False) -> List[str]:
    """Build the exact argv for a unit action. Raises ValueError on bad input."""
    if action not in UNIT_ACTIONS:
        raise ValueError("unknown action %r" % (action,))
    if not validate_unit(unit):
        raise ValueError("invalid unit name")
    base = ["systemctl", "--no-ask-password"]
    if action == "kill":
        sig = sig or "SIGTERM"
        if sig not in SIGNALS:
            raise ValueError("signal must be SIGTERM or SIGKILL")
        return base + ["kill", "--signal=" + sig, "--", unit]
    if action == "ipaccounting":
        return base + ["set-property", "--runtime", "--", unit, "IPAccounting=yes"]
    if action in ("disable", "mask") and now:
        return base + [action, "--now", "--", unit]
    return base + [action, "--", unit]


def build_pid_command(pid: int, sig: str) -> List[str]:
    """Equivalent shell command (for display/audit). Execution uses os.kill()."""
    if sig not in SIGNALS:
        raise ValueError("signal must be SIGTERM or SIGKILL")
    return ["kill", "-" + sig[3:], str(int(pid))]


def ssh_session_active(proc: str = procnet.PROC) -> bool:
    """True if any `sshd: user@pts/N` style per-session process exists."""
    try:
        pids = [d for d in os.listdir(proc) if d.isdigit()]
    except OSError:
        return False
    for d in pids:
        try:
            with open(os.path.join(proc, d, "cmdline"), "rb") as fh:
                cmd = fh.read(200).replace(b"\0", b" ").decode("utf-8", "replace")
        except OSError:
            continue
        if cmd.startswith("sshd: ") and "@" in cmd:
            return True
    return False


class Policy:
    def __init__(self, denylist: Optional[Iterable[Tuple[str, str]]] = None,
                 extra: Iterable[str] = (), self_unit: Optional[str] = None,
                 ssh_check: Callable[[], bool] = ssh_session_active):
        self.denylist = list(DEFAULT_DENYLIST if denylist is None else denylist)
        self.denylist += [(p, "user-configured (--deny)") for p in extra]
        if self_unit:
            self.denylist.append((self_unit, "this backend itself"))
        self.ssh_check = ssh_check

    def deny_reason(self, unit: Optional[str]) -> Optional[str]:
        if not unit:
            return None
        for pat, why in self.denylist:
            if fnmatch.fnmatchcase(unit, pat):
                return why
        if unit in SSH_UNITS and self.ssh_check():
            return "an SSH session is active (you may be connected through it)"
        return None

    def check_unit(self, action: str, unit: str) -> Optional[str]:
        return self.deny_reason(unit) if action in DESTRUCTIVE else None


def detect_self_unit(proc: str = procnet.PROC) -> Optional[str]:
    u = procnet.pid_unit(os.getpid(), proc)
    return u if u and u.endswith(".service") else None


class AuditLog:
    def __init__(self, path: Optional[str]):
        self.path = path
        self._lock = threading.Lock()
        if path:
            d = os.path.dirname(path)
            if d:
                os.makedirs(d, mode=0o750, exist_ok=True)

    def write(self, **rec):
        rec = dict(ts=_dt.datetime.now().astimezone().isoformat(timespec="seconds"), **rec)
        line = json.dumps(rec, sort_keys=True)
        if not self.path:
            return rec
        with self._lock:
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        return rec


class ActionError(Exception):
    def __init__(self, status: int, msg: str, **extra):
        super().__init__(msg)
        self.status, self.msg, self.extra = status, msg, extra


class Executor:
    def __init__(self, policy: Policy, audit: AuditLog, runner: Runner = default_runner,
                 dry_run: bool = False, read_only: bool = False,
                 proc: str = procnet.PROC, killer: Callable[[int, int], None] = os.kill,
                 on_change: Optional[Callable[[], None]] = None):
        self.policy, self.audit, self.runner = policy, audit, runner
        self.dry_run, self.read_only, self.proc = dry_run, read_only, proc
        self.killer, self.on_change = killer, on_change

    # ---------------- preview (no side effects) ----------------
    def preview_unit(self, action, unit, sig=None, now=False) -> dict:
        cmd = build_unit_command(action, unit, sig, bool(now))
        reason = self.policy.check_unit(action, unit)
        return {"cmd": cmd, "requires_force": reason is not None, "deny_reason": reason,
                "danger": action in DANGER, "dry_run": self.dry_run, "read_only": self.read_only}

    def _check_pid(self, pid, inode) -> dict:
        if isinstance(pid, bool) or not isinstance(pid, int):
            raise ActionError(400, "pid must be an integer")
        if pid <= 1:
            raise ActionError(403, "refusing to signal PID %d" % pid)
        if pid in (os.getpid(), os.getppid()):
            raise ActionError(403, "refusing to signal this backend (or its parent)")
        base = os.path.join(self.proc, str(pid))
        if not os.path.isdir(base):
            raise ActionError(404, "no such process %d" % pid)
        status = procnet.read_text(os.path.join(base, "status"))
        m = re.search(r"^PPid:\s*(\d+)", status, re.M)
        if m and int(m.group(1)) == 2 or pid == 2:
            raise ActionError(403, "refusing to signal a kernel thread")
        if isinstance(inode, bool) or not isinstance(inode, int):
            raise ActionError(400, "inode (int) is required to guard against PID reuse")
        if not procnet.pid_has_inode(pid, inode, self.proc):
            raise ActionError(409, "PID %d no longer owns socket inode %d (stale view?)" % (pid, inode))
        unit = procnet.pid_unit(pid, self.proc)
        return {"unit": unit, "process": procnet.read_comm(pid, self.proc),
                "deny_reason": self.policy.deny_reason(unit)}

    def preview_pid(self, pid, inode, sig="SIGTERM") -> dict:
        info = self._check_pid(pid, inode)
        return {"cmd": build_pid_command(pid, sig), "requires_force": info["deny_reason"] is not None,
                "deny_reason": info["deny_reason"], "unit": info["unit"], "process": info["process"],
                "danger": True, "dry_run": self.dry_run, "read_only": self.read_only}

    # ---------------- execution ----------------
    def run_unit(self, action, unit, sig=None, now=False, force=False, client="?") -> dict:
        try:
            cmd = build_unit_command(action, unit, sig, bool(now))
        except ValueError as e:
            self.audit.write(client=client, action=action, target=str(unit)[:256], result="invalid", reason=str(e))
            raise ActionError(400, str(e))
        base = dict(client=client, action=action, target=unit, cmd=cmd, dry_run=self.dry_run, forced=bool(force))
        if self.read_only:
            self.audit.write(result="refused", reason="read-only mode", **base)
            raise ActionError(403, "server is in --read-only mode")
        reason = self.policy.check_unit(action, unit)
        if reason and force is not True:
            self.audit.write(result="refused", reason="critical unit: " + reason, **base)
            raise ActionError(403, "%s is protected: %s. Resend with force=true to override." % (unit, reason),
                              requires_force=True, deny_reason=reason, cmd=cmd)
        if self.dry_run:
            self.audit.write(result="dry-run", rc=0, **base)
            return {"ok": True, "dry_run": True, "cmd": cmd, "rc": 0, "stdout": "", "stderr": "",
                    "message": "DRY-RUN: not executed"}
        rc, out, err = self.runner(cmd, 60)
        self.audit.write(result="ok" if rc == 0 else "error", rc=rc, stderr=err[-500:], **base)
        if self.on_change:
            self.on_change()
        return {"ok": rc == 0, "dry_run": False, "cmd": cmd, "rc": rc,
                "stdout": out[-2000:], "stderr": err[-2000:],
                "message": "done" if rc == 0 else (err.strip() or "failed (rc=%d)" % rc)}

    def kill_pid(self, pid, inode, sig="SIGTERM", force=False, client="?") -> dict:
        base = dict(client=client, action="kill-pid", target=str(pid)[:32], dry_run=self.dry_run, forced=bool(force))
        try:
            cmd = build_pid_command(pid if isinstance(pid, int) and not isinstance(pid, bool) else -1, sig)
            if self.read_only:
                raise ActionError(403, "server is in --read-only mode")
            info = self._check_pid(pid, inode)
        except (ValueError, ActionError) as e:
            err = e if isinstance(e, ActionError) else ActionError(400, str(e))
            self.audit.write(result="refused", reason=err.msg, **base)
            raise err
        base.update(cmd=cmd, process=info["process"], unit=info["unit"], inode=inode)
        if info["deny_reason"] and force is not True:
            self.audit.write(result="refused", reason="critical unit: " + info["deny_reason"], **base)
            raise ActionError(403, "PID %d belongs to %s (%s). Resend with force=true to override."
                              % (pid, info["unit"], info["deny_reason"]), requires_force=True,
                              deny_reason=info["deny_reason"], cmd=cmd)
        if self.dry_run:
            self.audit.write(result="dry-run", rc=0, **base)
            return {"ok": True, "dry_run": True, "cmd": cmd, "rc": 0, "message": "DRY-RUN: not executed"}
        try:
            self.killer(pid, SIGNALS[sig])
        except OSError as e:
            self.audit.write(result="error", reason=str(e), **base)
            return {"ok": False, "dry_run": False, "cmd": cmd, "rc": 1, "message": str(e)}
        self.audit.write(result="ok", rc=0, **base)
        return {"ok": True, "dry_run": False, "cmd": cmd, "rc": 0, "message": "signal sent"}
