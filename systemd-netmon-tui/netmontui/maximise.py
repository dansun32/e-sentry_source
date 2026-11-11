"""Self-maximisation.

Two paths:
  1. spawn: not on a TTY (desktop launcher) or --spawn -> re-exec inside a terminal emulator
     started with its own maximise flag.
  2. in place: already on a TTY -> ask the window manager (wmctrl by $WINDOWID, wmctrl
     :ACTIVE:, xdotool), else the xterm window-op escape CSI 9;1t.  Wayland: warn only.

Everything that decides *what* to run is a pure function (tested offline); execution is
injectable.
"""
from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
import time
from typing import Callable, Dict, List, Optional, Sequence, Tuple

Which = Callable[[str], Optional[str]]
MAX_PROPS = "add,maximized_vert,maximized_horz"

# name -> (builder(cmd) -> argv, has_native_maximise)
def _gnome(cmd):  return ["gnome-terminal", "--maximize", "--"] + list(cmd)
def _xfce(cmd):   return ["xfce4-terminal", "--maximize", "-x"] + list(cmd)
def _mate(cmd):   return ["mate-terminal", "--maximize", "-x"] + list(cmd)
def _tilix(cmd):  return ["tilix", "--maximize", "-e", " ".join(shlex.quote(c) for c in cmd)]
def _konsole(cmd): return ["konsole", "-e"] + list(cmd)          # no --maximize; in-place step follows
def _kitty(cmd):  return ["kitty", "--start-as=maximized"] + list(cmd)
def _xterm(cmd):  return ["xterm", "-maximized", "-e"] + list(cmd)
def _xte(cmd):    return ["x-terminal-emulator", "-e"] + list(cmd)  # Debian alternatives contract

TERMINALS: Dict[str, Tuple[Callable[[Sequence[str]], List[str]], bool]] = {
    "gnome-terminal": (_gnome, True), "xfce4-terminal": (_xfce, True),
    "mate-terminal": (_mate, True), "tilix": (_tilix, True), "konsole": (_konsole, False),
    "kitty": (_kitty, True), "xterm": (_xterm, True), "x-terminal-emulator": (_xte, False),
}
DEFAULT_ORDER = ["gnome-terminal", "xfce4-terminal", "mate-terminal", "tilix", "konsole",
                 "kitty", "xterm", "x-terminal-emulator"]
DESKTOP_PREF = [("CINNAMON", "gnome-terminal"), ("GNOME", "gnome-terminal"), ("UNITY", "gnome-terminal"),
                ("XFCE", "xfce4-terminal"), ("MATE", "mate-terminal"), ("KDE", "konsole"),
                ("LXQT", "x-terminal-emulator")]


def is_wayland(env: Dict[str, str]) -> bool:
    return env.get("XDG_SESSION_TYPE", "").lower() == "wayland" or (
        bool(env.get("WAYLAND_DISPLAY")) and not env.get("DISPLAY"))


def has_gui(env: Dict[str, str]) -> bool:
    return bool(env.get("DISPLAY") or env.get("WAYLAND_DISPLAY"))


def terminal_order(env: Dict[str, str], preferred: Optional[str] = None) -> List[str]:
    order: List[str] = []
    for p in (preferred, env.get("NETMON_TERMINAL")):
        if p and p not in order:
            order.append(p)
    desk = env.get("XDG_CURRENT_DESKTOP", "").upper()
    for key, term in DESKTOP_PREF:
        if key in desk and term not in order:
            order.append(term)
    order += [t for t in DEFAULT_ORDER if t not in order]
    return order


def choose_terminal(cmd: Sequence[str], env: Dict[str, str], which: Which = shutil.which,
                    preferred: Optional[str] = None) -> Optional[Tuple[str, List[str], bool]]:
    """Return (terminal, argv, native_maximise) for the first installed terminal, or None."""
    for name in terminal_order(env, preferred):
        if name not in TERMINALS or not which(name):
            continue
        build, native = TERMINALS[name]
        return name, build(cmd), native
    return None


def spawn_in_terminal(cmd: Sequence[str], env: Dict[str, str], preferred: Optional[str] = None,
                      which: Which = shutil.which, popen=subprocess.Popen) -> Tuple[bool, str]:
    if not has_gui(env):
        return False, "no DISPLAY/WAYLAND_DISPLAY: cannot open a terminal window"
    choice = choose_terminal(cmd, env, which, preferred)
    if not choice:
        return False, "no supported terminal emulator found (tried: %s)" % ", ".join(terminal_order(env, preferred))
    name, argv, _ = choice
    popen(argv, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
          stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True)
    return True, "spawned %s: %s" % (name, " ".join(shlex.quote(a) for a in argv))


# ----------------------------------------------------------------------------- in place
def plan_inplace(env: Dict[str, str], which: Which = shutil.which) -> Tuple[List[Tuple[str, Optional[List[str]]]], Optional[str]]:
    """Ordered list of (method, argv|None for escape sequence); plus a warning if any."""
    if is_wayland(env):
        return [], ("Wayland session: windows can't be maximised from inside; "
                    "use the terminal's maximise button or launch with --spawn")
    steps: List[Tuple[str, Optional[List[str]]]] = []
    wid = env.get("WINDOWID", "")
    wid = wid if wid.isdigit() and int(wid) > 0 else ""
    if env.get("DISPLAY"):
        if which("wmctrl"):
            if wid:
                steps.append(("wmctrl-windowid", ["wmctrl", "-i", "-r", "0x%x" % int(wid), "-b", MAX_PROPS]))
            steps.append(("wmctrl-active", ["wmctrl", "-r", ":ACTIVE:", "-b", MAX_PROPS]))
        if which("xdotool"):
            if wid:
                steps.append(("xdotool-windowstate", ["xdotool", "windowstate", "--add",
                              "MAXIMIZED_VERT,MAXIMIZED_HORZ", wid]))
                steps.append(("xdotool-size", ["xdotool", "windowmove", wid, "0", "0",
                              "windowsize", wid, "100%", "100%"]))
            else:
                steps.append(("xdotool-windowstate", ["xdotool", "getactivewindow", "windowstate",
                              "--add", "MAXIMIZED_VERT,MAXIMIZED_HORZ"]))
                steps.append(("xdotool-size", ["xdotool", "getactivewindow", "windowmove", "0", "0",
                              "windowsize", "100%", "100%"]))
    term = env.get("TERM", "")
    if term.startswith(("xterm", "rxvt")) and not env.get("VTE_VERSION"):
        steps.append(("csi-9-1t", None))  # xterm window op: maximise
    warn = None if steps else ("no maximise method available (need DISPLAY + wmctrl/xdotool, or an xterm)")
    return steps, warn


def recover_gui_env(env: Dict[str, str], proc: str = "/proc", start_pid: Optional[int] = None,
                    depth: int = 8) -> Dict[str, str]:
    """Under sudo, DISPLAY/XAUTHORITY/WINDOWID are often stripped. Root may read them back
    from the ancestor shell's /proc/PID/environ."""
    keys = ("DISPLAY", "XAUTHORITY", "WINDOWID", "WAYLAND_DISPLAY", "XDG_SESSION_TYPE", "XDG_RUNTIME_DIR")
    out = dict(env)
    pid = start_pid if start_pid is not None else os.getppid()
    for _ in range(depth):
        if pid <= 1 or all(out.get(k) for k in keys[:3]):
            break
        try:
            with open(os.path.join(proc, str(pid), "environ"), "rb") as fh:
                pairs = [p.split(b"=", 1) for p in fh.read().split(b"\0") if b"=" in p]
            penv = {k.decode(errors="replace"): v.decode(errors="replace") for k, v in pairs}
        except OSError:
            penv = {}
        for k in keys:
            if not out.get(k) and penv.get(k):
                out[k] = penv[k]
        try:
            with open(os.path.join(proc, str(pid), "stat")) as fh:
                pid = int(fh.read().rsplit(")", 1)[1].split()[1])
        except (OSError, ValueError, IndexError):
            break
    if out.get("DISPLAY") and not out.get("XAUTHORITY") and env.get("SUDO_USER"):
        try:
            import pwd
            cand = os.path.join(pwd.getpwnam(env["SUDO_USER"]).pw_dir, ".Xauthority")
            if os.path.exists(cand):
                out["XAUTHORITY"] = cand
        except KeyError:
            pass
    return out


def _run(argv, env, timeout=3.0) -> Tuple[int, str]:
    try:
        p = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout + p.stderr).strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        return 127, str(e)


def window_maximised(env, wid: Optional[str], which: Which = shutil.which) -> Optional[bool]:
    """True/False via xprop _NET_WM_STATE; None if unknown."""
    if not env.get("DISPLAY") or not which("xprop"):
        return None
    if not wid:
        rc, out = _run(["xprop", "-root", "_NET_ACTIVE_WINDOW"], env)
        if rc != 0 or "#" not in out:
            return None
        wid = out.rsplit("#", 1)[1].strip().split(",")[0]
    else:
        wid = "0x%x" % int(wid) if wid.isdigit() else wid
    rc, out = _run(["xprop", "-id", wid, "_NET_WM_STATE"], env)
    if rc != 0:
        return None
    return "_NET_WM_STATE_MAXIMIZED_VERT" in out and "_NET_WM_STATE_MAXIMIZED_HORZ" in out


def _tty_size(fd) -> Optional[Tuple[int, int]]:
    try:
        s = os.get_terminal_size(fd)
        return s.columns, s.lines
    except OSError:
        return None


def maximise_inplace(env: Dict[str, str], which: Which = shutil.which, tty_path: str = "/dev/tty",
                     settle: float = 0.6) -> List[str]:
    """Try the plan until one step is verified. Returns a human-readable report."""
    report: List[str] = []
    steps, warn = plan_inplace(env, which)
    if warn:
        report.append("maximise: " + warn)
    if not steps:
        return report
    wid = env.get("WINDOWID") if (env.get("WINDOWID") or "").isdigit() else None
    if window_maximised(env, wid, which):
        report.append("maximise: window already maximised")
        return report
    fd = None
    try:
        fd = os.open(tty_path, os.O_RDWR | os.O_NOCTTY)
    except OSError:
        pass
    before = _tty_size(fd) if fd is not None else None
    try:
        for name, argv in steps:
            if argv is None:
                if fd is None:
                    continue
                os.write(fd, b"\x1b[9;1t")
                rc, out = 0, "sent CSI 9;1t"
            else:
                rc, out = _run(argv, env)
            if rc != 0:
                report.append("maximise: %s failed (rc=%d) %s" % (name, rc, out[:120]))
                continue
            # verify: WM state, or the tty grew
            deadline = time.monotonic() + settle
            ok = None
            while time.monotonic() < deadline:
                st = window_maximised(env, wid if name != "wmctrl-active" else None, which) if argv else None
                after = _tty_size(fd) if fd is not None else None
                if st or (before and after and (after[0] > before[0] or after[1] > before[1])):
                    ok = True
                    break
                time.sleep(0.05)
            if ok:
                report.append("maximise: OK via %s" % name)
                return report
            report.append("maximise: %s ran but could not be verified" % name)
            if name.startswith("wmctrl") and window_maximised(env, None, which) is None:
                return report  # no way to verify; assume it worked rather than stacking methods
    finally:
        if fd is not None:
            os.close(fd)
    return report
