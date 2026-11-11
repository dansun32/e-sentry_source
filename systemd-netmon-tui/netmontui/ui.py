"""curses UI modelled on the systemd-netmon mockup: header bar, summary bar, services pane,
raw/packet sockets pane, status line and footer key bar, plus menu / confirm / drawer overlays."""
from __future__ import annotations

import curses
import locale
import os
import platform
import shlex
import threading
import time
from typing import Dict, List, Optional, Tuple

from . import NAME, __version__
from .actions import ActionError, DANGER, Executor
from .fmt import clip, fmt_bytes, fmt_kbps, layout_columns, sparkline, split_heights, wrap
from .systemd import Sampler

MIN_W, MIN_H = 80, 20
VIEWS = ("running", "all", "accounting")
INTERVALS = {ord("1"): 0.5, ord("2"): 1.0, ord("3"): 2.0}
RUNNING_STATES = ("active", "activating", "deactivating", "reloading")

UNIT_MENU = [  # (hotkey, label, action, signal, style, predicate)
    ("S", "Start", "start", None, "ok", lambda s: s["active_state"] not in RUNNING_STATES),
    ("s", "Stop", "stop", None, "warn", None),
    ("r", "Restart", "restart", None, "warn", None),
    ("t", "Kill (SIGTERM)", "kill", "SIGTERM", "danger", None),
    ("k", "Kill (SIGKILL)", "kill", "SIGKILL", "danger", None),
    ("e", "Enable at boot", "enable", None, "ok", lambda s: s["unit_file_state"] == "disabled"),
    ("D", "Disable at boot", "disable", None, "warn",
     lambda s: s["unit_file_state"] not in ("disabled", "masked", "masked-runtime", "static")),
    ("m", "Mask (block all starts)", "mask", None, "danger", lambda s: not s["unit_file_state"].startswith("masked")),
    ("u", "Unmask", "unmask", None, "ok", lambda s: s["unit_file_state"].startswith("masked")),
    ("i", "Enable IPAccounting (runtime)", "ipaccounting", None, "ok", lambda s: not s["accounting_active"]),
]
NOTES = {
    "kill": "Signals every process in the unit. Units with Restart= may respawn immediately.",
    "mask": "Links the unit to /dev/null: nothing can start it until unmasked.",
    "disable": "Prevents start at boot; sockets/dependencies may still start it.",
    "stop": "Runtime only; it starts again at next boot if enabled.",
    "restart": "Stops and starts the unit.",
    "ipaccounting": "Runtime only (lost at reboot). Counters start from zero now.",
}
HELP = [
    ("Space", "pause / resume polling"), ("/", "filter (Enter keep, Esc clear)"),
    ("r", "reset totals + sparklines (display only)"), ("+ / -", "slower / faster refresh"),
    ("1 2 3", "refresh 0.5s / 1s / 2s"), ("Tab", "switch pane"), ("↑↓ j k PgUp PgDn Home End", "select"),
    ("Enter / a", "action menu for selected row"), ("d", "details / info drawer"),
    ("v", "view: running / all / IPAccounting on"), ("?", "this help"), ("q", "quit (Esc closes overlays)"),
]
REFERENCE = """Rates come from `systemctl show -p IPIngressBytes,IPEgressBytes,...` deltas. They exist only for units with IPAccounting=yes (eBPF on the unit's cgroup); everything else shows n/a and is never invented. Enable per unit from the action menu (runtime) or persistently with `sudo systemctl set-property UNIT IPAccounting=yes`, or for all services with DefaultIPAccounting=yes in /etc/systemd/system.conf.

Raw/packet sockets come from /proc/net/raw, raw6 and packet; owners are found via /proc/*/fd (root needed for other users). The kernel exposes no per-socket packet counters for these sockets, so packet rate is n/a; drops (raw) and Rmem (packet) are real.

Destructive actions (stop/restart/kill/disable/mask) on protected units require typing the unit name. Every attempt goes to the audit log."""


# ----------------------------------------------------------------------------- theme
class Theme:
    def __init__(self, mode: str):
        A = curses
        self.mode = mode
        n = dict(text=A.A_NORMAL, dim=A.A_DIM, cyan=A.A_BOLD, green=A.A_BOLD, amber=A.A_BOLD,
                 red=A.A_BOLD | A.A_UNDERLINE, bar=A.A_REVERSE, bar_cyan=A.A_REVERSE | A.A_BOLD,
                 bar_green=A.A_REVERSE | A.A_BOLD, bar_amber=A.A_REVERSE | A.A_BOLD,
                 bar_red=A.A_REVERSE | A.A_BOLD, bar_dim=A.A_REVERSE, key=A.A_REVERSE | A.A_BOLD,
                 sel=A.A_REVERSE, border=A.A_DIM, border_focus=A.A_BOLD, white=A.A_BOLD)
        if mode in ("256", "8"):
            rich = mode == "256"
            fg = dict(cyan=(51 if rich else A.COLOR_CYAN), green=(48 if rich else A.COLOR_GREEN),
                      amber=(214 if rich else A.COLOR_YELLOW), red=(203 if rich else A.COLOR_RED),
                      slate=(250 if rich else A.COLOR_WHITE), dim=(242 if rich else A.COLOR_WHITE),
                      white=(255 if rich else A.COLOR_WHITE), border=(238 if rich else A.COLOR_BLUE),
                      focus=(37 if rich else A.COLOR_CYAN))
            bar_bg = 235 if rich else A.COLOR_BLUE
            sel_bg = 24 if rich else A.COLOR_CYAN
            pairs = {}

            def pair(f, b=-1):
                if (f, b) not in pairs:
                    i = len(pairs) + 1
                    A.init_pair(i, f, b)
                    pairs[(f, b)] = A.color_pair(i)
                return pairs[(f, b)]
            n.update(text=pair(fg["slate"]), dim=pair(fg["dim"]) | (0 if rich else A.A_DIM),
                     cyan=pair(fg["cyan"]), green=pair(fg["green"]), amber=pair(fg["amber"]),
                     red=pair(fg["red"]), white=pair(fg["white"]) | A.A_BOLD,
                     bar=pair(fg["slate"], bar_bg), bar_cyan=pair(fg["cyan"], bar_bg) | A.A_BOLD,
                     bar_green=pair(fg["green"], bar_bg) | A.A_BOLD, bar_amber=pair(fg["amber"], bar_bg) | A.A_BOLD,
                     bar_red=pair(fg["red"], bar_bg) | A.A_BOLD, bar_dim=pair(fg["dim"], bar_bg),
                     key=pair(A.COLOR_BLACK, fg["cyan"]) | A.A_BOLD,
                     sel=pair(fg["white"], sel_bg) | A.A_BOLD,
                     border=pair(fg["border"]), border_focus=pair(fg["focus"]) | A.A_BOLD)
        self.a = n

    def __getitem__(self, k):
        return self.a[k]


def detect_color_mode(requested: str = "auto") -> str:
    if requested != "auto":
        return requested
    if os.environ.get("NO_COLOR") or not curses.has_colors():
        return "mono"
    return "256" if curses.COLORS >= 256 else "8"


def unicode_ok() -> bool:
    return "UTF-8" in (locale.getpreferredencoding(False) or "").upper()


class Canvas:
    def __init__(self, win, uni: bool = True):
        self.win, self.uni = win, uni
        self.bx = "─│┌┐└┘" if uni else "-|++++"

    def size(self):
        return self.win.getmaxyx()

    def put(self, y, x, text, attr=0, width=None):
        h, w = self.win.getmaxyx()
        if y < 0 or y >= h or x >= w:
            return 0
        if x < 0:
            text, x = str(text)[-x:], 0
        maxw = w - x if width is None else min(width, w - x)
        s = clip(text, maxw) if width is None else clip(text, maxw).ljust(maxw)
        if not self.uni:
            s = s.encode("ascii", "replace").decode()
        if y == h - 1 and x + len(s) >= w:
            s = s[: max(0, w - x - 1)]
        try:
            self.win.addstr(y, x, s, attr)
        except curses.error:
            pass
        return len(s)

    def fill(self, y, x, width, attr=0):
        self.put(y, x, " " * max(0, width), attr)

    def box(self, y, x, h, w, attr, title="", title_attr=0, right="", right_attr=0):
        if h < 2 or w < 2:
            return
        b = self.bx
        self.put(y, x, b[2] + b[0] * (w - 2) + b[3], attr)
        for i in range(1, h - 1):
            self.put(y + i, x, b[1], attr)
            self.put(y + i, x + w - 1, b[1], attr)
        self.put(y + h - 1, x, b[4] + b[0] * (w - 2) + b[5], attr)
        if title:
            self.put(y, x + 2, " " + clip(title, w - 6) + " ", title_attr)
        if right and w > len(title) + len(right) + 10:
            self.put(y, x + w - len(right) - 4, " " + right + " ", right_attr)

    def panel(self, y, x, h, w, attr):
        for i in range(h):
            self.fill(y + i, x, w, attr)


# ----------------------------------------------------------------------------- poller
class Poller(threading.Thread):
    def __init__(self, sampler: Sampler, interval: float):
        super().__init__(daemon=True)
        self.sampler, self.interval = sampler, interval
        self.paused = False
        self.snap: Optional[dict] = None
        self.error: Optional[str] = None
        self.version = 0
        self._wake = threading.Event()
        self._stop = threading.Event()

    def kick(self):
        self._wake.set()

    def stop(self):
        self._stop.set()
        self._wake.set()

    def run(self):
        while not self._stop.is_set():
            if not self.paused:
                try:
                    self.snap = self.sampler.sample()
                    self.error = None
                except Exception as e:  # keep the UI alive whatever happens
                    self.error = "%s: %s" % (type(e).__name__, e)
                self.version += 1
            self._wake.wait(self.interval)
            self._wake.clear()


def os_label() -> str:
    name = ""
    try:
        with open("/etc/os-release", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("PRETTY_NAME="):
                    name = line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return "%s / Linux %s" % (name or platform.system(), platform.release())


# ----------------------------------------------------------------------------- app
class App:
    def __init__(self, sampler: Sampler, executor: Executor, interval: float = 1.0,
                 color: str = "auto", startup_notes: Optional[List[str]] = None):
        self.sampler, self.ex = sampler, executor
        self.poller = Poller(sampler, interval)
        self.color_req = color
        self.view = 0
        self.filter = ""
        self.filtering = False
        self.focus = 0
        self.sel_key: List[Optional[object]] = [None, None]
        self.scroll = [0, 0]
        self.baseline: Dict[str, int] = {}
        self.overlay: Optional[str] = None
        self.menu: dict = {}
        self.confirm: dict = {}
        self.drawer_scroll = 0
        self.status: Tuple[str, str, float] = ("", "text", 0.0)
        self.os_label = os_label()
        self.host = platform.node()
        self.startup_notes = startup_notes or []
        self.theme: Optional[Theme] = None
        self._peak = 1.0
        self.cv: Optional[Canvas] = None
        self.rows_cache: Tuple[list, list] = ([], [])

    # ------------------------------------------------------------------ lifecycle
    def run(self):
        curses.wrapper(self._main)

    def _main(self, scr):
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        if curses.has_colors():
            curses.start_color()
            try:
                curses.use_default_colors()
            except curses.error:
                pass
        self.attach(scr, detect_color_mode(self.color_req), unicode_ok())
        scr.keypad(True)
        scr.timeout(100)
        self.poller.start()
        if self.startup_notes:
            self.set_status(" | ".join(self.startup_notes), "amber", 10)
        try:
            while True:
                self.draw()
                ch = scr.getch()
                if ch == -1:
                    continue
                if ch == curses.KEY_RESIZE:
                    curses.update_lines_cols()
                    scr.erase()
                    continue
                if self.handle_key(ch) is False:
                    break
        finally:
            self.poller.stop()

    def attach(self, scr, color_mode: str, uni: bool):
        self.scr = scr
        self.theme = Theme(color_mode)
        self.cv = Canvas(scr, uni)

    def set_status(self, text, kind="text", secs=8.0):
        self.status = (text, kind, time.monotonic() + secs)

    # ------------------------------------------------------------------ data
    @property
    def snap(self) -> dict:
        return self.poller.snap or {"services": [], "sockets": [], "totals": {}}

    def rows(self):
        snap = self.snap
        q = self.filter.lower()
        svcs = [s for s in snap["services"] if q in s["unit"].lower() or q in (s.get("description") or "").lower()]
        v = VIEWS[self.view]
        if v == "running":
            svcs = [s for s in svcs if s["active_state"] in RUNNING_STATES]
        elif v == "accounting":
            svcs = [s for s in svcs if s["accounting_active"]]
        svcs.sort(key=lambda s: (-((s.get("in_bps") or 0) + (s.get("out_bps") or 0)),
                                 not s["accounting_active"], s["unit"]))
        socks = [x for x in snap["sockets"] if not q or q in (x.get("process") or "").lower()
                 or q in x["proto"].lower() or q in (x.get("unit") or "").lower()]
        self.rows_cache = (svcs, socks)
        return svcs, socks

    @staticmethod
    def row_key(pane, r):
        return r["unit"] if pane == 0 else (r["kind"], r["inode"])

    def sel_index(self, pane, rows):
        key = self.sel_key[pane]
        for i, r in enumerate(rows):
            if self.row_key(pane, r) == key:
                return i
        if rows:
            self.sel_key[pane] = self.row_key(pane, rows[0])
        return 0

    def selected(self):
        svcs, socks = self.rows()
        rows = svcs if self.focus == 0 else socks
        if not rows:
            return None
        return rows[self.sel_index(self.focus, rows)]

    def move(self, delta=None, to=None):
        svcs, socks = self.rows()
        rows = svcs if self.focus == 0 else socks
        if not rows:
            return
        i = self.sel_index(self.focus, rows)
        i = to if to is not None else i + delta
        i = max(0, min(len(rows) - 1, i))
        self.sel_key[self.focus] = self.row_key(self.focus, rows[i])

    # ------------------------------------------------------------------ drawing
    def draw(self):
        cv, T = self.cv, self.theme
        self.scr.erase()
        h, w = cv.size()
        if h < MIN_H or w < MIN_W:
            cv.put(0, 0, "%s: terminal is %dx%d, need at least %dx%d." % (NAME, w, h, MIN_W, MIN_H), T["amber"])
            cv.put(1, 0, "Maximise the window (or run with --spawn). q quits.", T["text"])
            self.scr.refresh()
            return
        svcs, socks = self.rows()
        self._peak = max([max(s.get("history") or [0]) for s in svcs] + [1.0])
        self.draw_header(0, w)
        self.draw_summary(1, w)
        svc_h, sock_h = split_heights(h, len(socks))
        sig = (h, w, svc_h)
        if sig != getattr(self, "_layout_sig", None):
            # pane geometry changed: force a full repaint instead of letting curses
            # optimise with scroll/insert-line sequences (some terminals mis-render those)
            self._layout_sig = sig
            if hasattr(self.scr, "clearok"):
                self.scr.clearok(True)
        self.draw_services(3, svc_h, w, svcs)
        self.draw_sockets(3 + svc_h, sock_h, w, socks)
        self.draw_status(h - 2, w)
        self.draw_footer(h - 1, w)
        if self.overlay == "drawer":
            self.draw_drawer(h, w)
        elif self.overlay == "menu":
            self.draw_menu(h, w)
        elif self.overlay == "confirm":
            self.draw_confirm(h, w)
        elif self.overlay == "help":
            self.draw_help(h, w)
        self.scr.refresh()

    def draw_header(self, y, w):
        cv, T = self.cv, self.theme
        cv.fill(y, 0, w, T["bar"])
        x = cv.put(y, 1, " >_ %s v%s " % (NAME, __version__), T["bar_cyan"]) + 1
        x += cv.put(y, x, " | ", T["bar_dim"])
        dot = "●" if cv.uni else "*"
        if self.poller.error:
            x += cv.put(y, x, dot + " SAMPLER ERROR", T["bar_red"])
        elif self.poller.paused:
            x += cv.put(y, x, dot + " PAUSED", T["bar_amber"])
        else:
            blink = int(time.monotonic() * 2) % 2 == 0
            x += cv.put(y, x, (dot if blink else " ") + " LIVE POLLING", T["bar_green"])
        if self.ex.read_only:
            badge, a = "[READ-ONLY]", T["bar_dim"]
        elif self.ex.dry_run:
            badge, a = "[DRY-RUN]", T["bar_amber"]
        else:
            badge, a = "[ACTIONS ARMED%s]" % (" root" if os.geteuid() == 0 else ""), T["bar_red"]
        x += cv.put(y, x, "  " + badge, a)
        right = "view:%s  every %ss  %s" % (VIEWS[self.view], ("%g" % self.poller.interval), self.host)
        mid = "  " + self.os_label
        room = w - x - len(right) - 2
        if room > 10:
            cv.put(y, x, clip(mid, room), T["bar"])
        cv.put(y, max(x, w - len(right) - 1), right, T["bar_dim"])

    def draw_summary(self, y, w):
        cv, T = self.cv, self.theme
        t = self.snap.get("totals", {})
        cells = [("SYSTEMD TOTAL INGRESS", "%s KB/s" % fmt_kbps(t.get("in_bps", 0)), T["bar_green"]),
                 ("SYSTEMD TOTAL EGRESS", "%s KB/s" % fmt_kbps(t.get("out_bps", 0)), T["bar_cyan"]),
                 ("RUNNING / LOADED (IPACCOUNTING)", "%d / %d (%d)" % (t.get("active_units", 0), t.get("units", 0),
                                                                      t.get("accounting_units", 0)), T["bar"]),
                 ("RAW / PACKET SOCKETS", "%d sockets active" % t.get("sockets", 0), T["bar_amber"])]
        cv.fill(y, 0, w, T["bar"])
        cv.fill(y + 1, 0, w, T["bar"])
        cw = w // 4
        for i, (label, val, a) in enumerate(cells):
            cv.put(y, 1 + i * cw, clip(label, cw - 2), T["bar_dim"])
            cv.put(y + 1, 1 + i * cw, clip(val, cw - 2), a)

    SVC_COLS = [("mark", 1, 0, 100), ("unit", 22, 3, 100), ("state", 24, 0, 60), ("thr", 15, 0, 100),
                ("io", 19, 0, 80), ("spark", 12, 2, 40), ("total", 10, 0, 90)]
    SVC_HEAD = {"unit": "SERVICE UNIT NAME", "state": "STATE", "thr": "THROUGHPUT", "io": "IN / OUT KB/s",
                "spark": "SPARKLINE", "total": "TOTAL DATA", "mark": ""}
    RIGHT = {"thr", "io", "total"}

    def draw_services(self, y, h, w, svcs):
        cv, T = self.cv, self.theme
        focus = self.focus == 0 and self.overlay != "menu"
        cv.box(y, 0, h, w, T["border_focus"] if self.focus == 0 else T["border"],
               "SYSTEMD NETWORK SERVICES (SORTED TOP-DOWN BY THROUGHPUT)", T["cyan"] | curses.A_BOLD,
               "rates need IPAccounting=yes", T["dim"])
        cols = layout_columns(self.SVC_COLS, w - 4)
        for key, x, cw in cols:
            txt = self.SVC_HEAD[key]
            cv.put(y + 1, 2 + x, txt.rjust(cw) if key in self.RIGHT else txt, T["dim"] | curses.A_BOLD, cw)
        body = h - 3
        if not svcs:
            err = self.snap.get("systemd_error")
            cv.put(y + 2, 2, "systemd unavailable: %s" % err if err else "No matching systemd units.", T["amber"] if err else T["dim"])
            return
        sel = self.sel_index(0, svcs)
        self.scroll[0] = self._scroll(self.scroll[0], sel, body, len(svcs))
        for row, s in enumerate(svcs[self.scroll[0]: self.scroll[0] + body]):
            idx = self.scroll[0] + row
            is_sel = idx == sel and self.focus == 0
            yy = y + 2 + row
            if is_sel:
                cv.fill(yy, 1, w - 2, T["sel"])
            for key, x, cw in cols:
                text, a = self._svc_cell(key, s, cw)
                if key in self.RIGHT:
                    text = text.rjust(cw)
                cv.put(yy, 2 + x, text, T["sel"] if is_sel else a, cw)
        self._scrollbar(y + 2, body, w - 1, self.scroll[0], len(svcs))

    def _svc_cell(self, key, s, cw):
        T, uni = self.theme, self.cv.uni
        acct = s["accounting_active"]
        rate = (s.get("in_bps") or 0) + (s.get("out_bps") or 0)
        if key == "mark":
            a = T["green"] if acct and rate > 0 else T["text"] if s["active_state"] == "active" else \
                T["red"] if s["active_state"] == "failed" else T["dim"]
            return ("●" if uni else "*"), a
        if key == "unit":
            prot = self.ex.policy.deny_reason(s["unit"]) is not None
            return s["unit"] + (" !" if prot else ""), T["white"]
        if key == "state":
            a = s["active_state"]
            col = T["green"] if a == "active" else T["red"] if a == "failed" else T["amber"] if a in RUNNING_STATES else T["dim"]
            uf = s["unit_file_state"]
            return "%s/%s %s" % (a, s["sub_state"], uf), (T["red"] if uf.startswith("masked") else col)
        if key == "thr":
            if not acct:
                return "n/a", T["dim"]
            if s.get("in_bps") is None:
                return "[… KBPS]", T["dim"]
            k = rate / 1024
            return "[%.2f KBPS]" % k, (T["green"] | curses.A_BOLD if k > 100 else T["cyan"] if k > 10 else T["text"])
        if key == "io":
            if not acct:
                return "IPAccounting off", T["dim"]
            dn, up = ("↓", "↑") if uni else ("v", "^")
            return "%s%s / %s%s" % (dn, fmt_kbps(s.get("in_bps")), up, fmt_kbps(s.get("out_bps"))), T["text"]
        if key == "spark":
            return (sparkline(s.get("history", []), min(cw, 40), uni, self._peak) if acct else ""), T["cyan"]
        if key == "total":
            if not acct:
                return "n/a", T["dim"]
            return fmt_bytes((s["in_bytes"] or 0) + (s["out_bytes"] or 0) - self.baseline.get(s["unit"], 0)), T["text"]
        return "", 0

    SOCK_COLS = [("inode", 9, 0, 100), ("proc", 14, 2, 100), ("pid", 8, 0, 100), ("proto", 24, 1, 100),
                 ("iface", 8, 0, 50), ("pkts", 6, 0, 30), ("drops", 16, 0, 70), ("unit", 14, 2, 60)]
    SOCK_HEAD = {"inode": "INODE", "proc": "PROCESS", "pid": "PID", "proto": "PROTOCOL / TYPE",
                 "iface": "IFACE", "pkts": "PKTS/S", "drops": "DROPS / RMEM", "unit": "UNIT"}

    def draw_sockets(self, y, h, w, socks):
        cv, T = self.cv, self.theme
        cv.box(y, 0, h, w, T["border_focus"] if self.focus == 1 else T["border"],
               "RAW / PACKET SOCKETS (BYPASS /etc/hosts.deny)", T["amber"] | curses.A_BOLD,
               "/proc/net/raw{,6} & /proc/net/packet", T["dim"])
        cols = layout_columns(self.SOCK_COLS, w - 4)
        for key, x, cw in cols:
            txt = self.SOCK_HEAD[key]
            cv.put(y + 1, 2 + x, txt.rjust(cw) if key in ("pkts", "drops") else txt, T["dim"] | curses.A_BOLD, cw)
        body = h - 3
        if not socks:
            cv.put(y + 2, 2, "No raw or packet sockets open.", T["dim"])
            return
        if not self.snap.get("sockets_pid_mapping_complete", True):
            cv.put(y + h - 1, 2, " some owners hidden: run as root ", T["amber"])
        sel = self.sel_index(1, socks)
        self.scroll[1] = self._scroll(self.scroll[1], sel, body, len(socks))
        for row, x_ in enumerate(socks[self.scroll[1]: self.scroll[1] + body]):
            idx = self.scroll[1] + row
            is_sel = idx == sel and self.focus == 1
            yy = y + 2 + row
            if is_sel:
                cv.fill(yy, 1, w - 2, T["sel"])
            for key, x, cw in cols:
                text, a = self._sock_cell(key, x_)
                if key in ("pkts", "drops"):
                    text = text.rjust(cw)
                cv.put(yy, 2 + x, text, T["sel"] if is_sel else a, cw)
        self._scrollbar(y + 2, body, w - 1, self.scroll[1], len(socks))

    def _sock_cell(self, key, x):
        T = self.theme
        if key == "inode":
            return "#%d" % x["inode"], T["dim"]
        if key == "proc":
            return (x.get("process") or "unknown"), (T["amber"] | curses.A_BOLD if x.get("process") else T["dim"])
        if key == "pid":
            if not x.get("pid"):
                return "?", T["dim"]
            more = len(x.get("pids", [])) - 1
            return "%d%s" % (x["pid"], "+%d" % more if more > 0 else ""), T["text"]
        if key == "proto":
            return x["proto"], T["text"]
        if key == "iface":
            return x.get("iface") or "-", T["dim"]
        if key == "pkts":
            return "n/a", T["dim"]
        if key == "drops":
            if x["kind"] == "packet":
                return "%s rmem" % fmt_bytes(x.get("rmem")), T["text"]
            if x.get("drops") is None:
                return "n/a", T["dim"]
            r = x.get("drop_rate")
            return "%d drops%s" % (x["drops"], " +%.1f/s" % r if r else ""), (T["red"] if r else T["text"])
        if key == "unit":
            return x.get("unit") or "", T["dim"]
        return "", 0

    @staticmethod
    def _scroll(top, sel, body, n):
        if body <= 0:
            return 0
        if sel < top:
            top = sel
        elif sel >= top + body:
            top = sel - body + 1
        return max(0, min(top, max(0, n - body)))

    def _scrollbar(self, y, body, x, top, n):
        if n <= body or body <= 0:
            return
        pos = int(top / max(1, n - body) * (body - 1))
        self.cv.put(y + pos, x, "█" if self.cv.uni else "#", self.theme["cyan"])

    def draw_status(self, y, w):
        cv, T = self.cv, self.theme
        if self.filtering:
            cv.put(y, 0, " filter: " + self.filter + "_", T["cyan"] | curses.A_BOLD, w)
            return
        text, kind, until = self.status
        if text and time.monotonic() < until:
            cv.put(y, 0, " " + text, T[kind] if kind in T.a else T["text"], w)
        elif self.filter:
            cv.put(y, 0, " filter: %s   (/ to edit, Esc in filter to clear)" % self.filter, T["dim"], w)

    def draw_footer(self, y, w):
        cv, T = self.cv, self.theme
        cv.fill(y, 0, w, T["bar"])
        keys = [("Space", "Pause"), ("/", "Filter"), ("r", "Reset"), ("Tab", "Pane"), ("Enter", "Actions"),
                ("d", "Details"), ("v", "View"), ("1/2/3", "Interval"), ("?", "Help"), ("q", "Quit")]
        x = 1
        for k, label in keys:
            need = len(k) + len(label) + 4
            if x + need >= w - 1:
                break
            x += cv.put(y, x, " %s " % k, T["key"])
            x += cv.put(y, x, " %s  " % label, T["bar"])
        right = "via systemctl -> org.freedesktop.systemd1"
        if w - x > len(right) + 2:
            cv.put(y, w - len(right) - 2, right, T["bar_dim"])

    # ------------------------------------------------------------------ overlays
    def _modal(self, h, w, mh, mw, border, title, title_attr):
        y, x = max(1, (h - mh) // 2), max(0, (w - mw) // 2)
        self.cv.panel(y, x, mh, mw, self.theme["text"])
        self.cv.box(y, x, mh, mw, border, title, title_attr)
        return y, x

    def menu_items(self, row, pane):
        if self.ex.read_only:
            return []
        if pane == 0:
            return [dict(key=k, label=l, kind="unit", unit=row["unit"], action=a, sig=sig, style=st)
                    for k, l, a, sig, st, pred in UNIT_MENU if pred is None or pred(row)]
        items = []
        if row.get("pid"):
            items += [dict(key="t", label="Kill PID %d (SIGTERM)" % row["pid"], kind="pid", pid=row["pid"],
                           inode=row["inode"], sig="SIGTERM", style="danger"),
                      dict(key="k", label="Kill PID %d (SIGKILL)" % row["pid"], kind="pid", pid=row["pid"],
                           inode=row["inode"], sig="SIGKILL", style="danger")]
            if (row.get("unit") or "").endswith(".service"):
                items.append(dict(key="s", label="Stop owning unit %s" % row["unit"], kind="unit",
                                  unit=row["unit"], action="stop", sig=None, style="warn"))
        return items

    def open_menu(self):
        row = self.selected()
        if row is None:
            return
        items = self.menu_items(row, self.focus)
        if not items:
            self.set_status("read-only mode: actions disabled" if self.ex.read_only
                            else "no actions: owner PID unknown (run as root)", "amber")
            return
        title = row["unit"] if self.focus == 0 else "%s pid %s" % (row.get("process") or "?", row.get("pid"))
        self.menu = dict(items=items, idx=0, title=title)
        self.overlay = "menu"

    def draw_menu(self, h, w):
        T = self.theme
        items = self.menu["items"]
        mw = min(w - 4, max(44, max(len(i["label"]) for i in items) + 12, len(self.menu["title"]) + 8))
        mh = len(items) + 4
        y, x = self._modal(h, w, mh, mw, T["border_focus"], "ACTIONS: " + self.menu["title"], T["cyan"] | curses.A_BOLD)
        for i, it in enumerate(items):
            a = {"danger": T["red"], "warn": T["amber"], "ok": T["text"]}[it["style"]]
            if i == self.menu["idx"]:
                a = T["sel"]
                self.cv.fill(y + 1 + i, x + 1, mw - 2, a)
            self.cv.put(y + 1 + i, x + 2, "[%s] %s" % (it["key"], it["label"]), a, mw - 4)
        self.cv.put(y + mh - 2, x + 2, "↑↓ select  Enter run  hotkey  Esc close" if self.cv.uni
                    else "up/down select  Enter run  hotkey  Esc close", T["dim"], mw - 4)

    def open_confirm(self, it):
        try:
            if it["kind"] == "unit":
                prev = self.ex.preview_unit(it["action"], it["unit"], it.get("sig"), it.get("now", False))
            else:
                prev = self.ex.preview_pid(it["pid"], it["inode"], it["sig"])
        except ActionError as e:
            self.overlay = None
            self.set_status("cannot prepare action: " + e.msg, "red")
            return
        except ValueError as e:
            self.overlay = None
            self.set_status("invalid: %s" % e, "red")
            return
        self.confirm = dict(it, preview=prev, typed="", now=it.get("now", False))
        self.overlay = "confirm"

    def draw_confirm(self, h, w):
        T, c = self.theme, self.confirm
        p = c["preview"]
        danger = c.get("action") in DANGER or c["kind"] == "pid"
        warn = c.get("action") in ("stop", "restart", "disable")
        border = T["red"] if danger or p["requires_force"] else T["amber"] if warn else T["cyan"]
        label = ("kill %s" % c["sig"] if c.get("action") == "kill" else c.get("action", "")) if c["kind"] == "unit" \
            else "kill PID %s (%s)" % (c["pid"], c["sig"])
        mw = min(w - 4, 84)
        iw = mw - 4
        cmd = "$ " + " ".join(shlex.quote(a) for a in p["cmd"]) + ("   # via os.kill()" if c["kind"] == "pid" else "")
        lines: List[Tuple[str, int]] = []
        if c["kind"] == "unit":
            lines.append(("Unit: " + c["unit"], T["white"]))
        else:
            lines.append(("Process: %s  PID %s  socket #%s%s" % (p.get("process"), c["pid"], c["inode"],
                          ("  unit " + p["unit"]) if p.get("unit") else ""), T["white"]))
        lines.append(("", 0))
        lines.append(("Exact command:", T["dim"]))
        lines += [(l, T["green"]) for l in wrap(cmd, iw)]
        lines.append(("", 0))
        note = NOTES.get(c.get("action", ""), "") if c["kind"] == "unit" else \
            "Sends %s directly to the process; a service with Restart= may come back." % c["sig"]
        lines += [(l, T["red"] if danger else T["text"]) for l in wrap(note, iw)] if note else []
        if c["kind"] == "unit" and c["action"] in ("disable", "mask"):
            lines.append(("[Space] also stop it now (--now): %s" % ("ON" if c["now"] else "off"), T["cyan"]))
        if p["dry_run"]:
            lines.append(("DRY-RUN: will be logged, not executed.", T["amber"] | curses.A_BOLD))
        if p["requires_force"]:
            want = c["unit"] if c["kind"] == "unit" else str(c["pid"])
            lines.append(("", 0))
            lines += [(l, T["red"] | curses.A_BOLD) for l in wrap("PROTECTED: %s." % p["deny_reason"], iw)]
            lines.append(("Type %s and press Enter to override:" % want, T["red"]))
            lines.append(("> " + c["typed"] + "_", T["white"]))
            foot = "Enter confirm   Esc cancel"
        else:
            foot = "Enter / y run   Esc / n cancel"
        mh = len(lines) + 4
        y, x = self._modal(h, w, mh, mw, border, label.upper(), border | curses.A_BOLD)
        for i, (t, a) in enumerate(lines):
            self.cv.put(y + 1 + i, x + 2, t, a, iw)
        self.cv.put(y + mh - 2, x + 2, foot + "   (audit-logged)", T["dim"], iw)

    def draw_help(self, h, w):
        T = self.theme
        mw, mh = min(w - 4, 70), len(HELP) + 4
        y, x = self._modal(h, w, mh, mw, T["border_focus"], "KEYS", T["cyan"] | curses.A_BOLD)
        for i, (k, d) in enumerate(HELP):
            self.cv.put(y + 1 + i, x + 2, k.ljust(26), T["cyan"])
            self.cv.put(y + 1 + i, x + 29, d, T["text"], mw - 31)
        self.cv.put(y + mh - 2, x + 2, "Esc / ? close", T["dim"])

    def drawer_lines(self, width) -> List[Tuple[str, str]]:
        out: List[Tuple[str, str]] = []
        row = self.selected()
        if row is not None:
            out.append(("SELECTED " + ("UNIT" if self.focus == 0 else "SOCKET"), "cyan"))
            keys = (["unit", "description", "load_state", "active_state", "sub_state", "unit_file_state", "main_pid",
                     "ip_accounting", "in_bytes", "out_bytes", "in_packets", "out_packets", "in_bps", "out_bps"]
                    if self.focus == 0 else
                    ["kind", "inode", "proto", "iface", "process", "pid", "pids", "unit", "uid", "local", "remote",
                     "drops", "drop_rate", "rx_queue", "tx_queue", "rmem", "running"])
            for k in keys:
                if k in row:
                    v = row[k]
                    v = "n/a" if v is None else ("%.1f" % v if isinstance(v, float) else v)
                    for l in wrap("%-16s %s" % (k, v), width):
                        out.append((l, "text"))
            reason = self.ex.policy.deny_reason(row["unit"] if self.focus == 0 else row.get("unit"))
            if reason:
                out.append(("protected (marked ! in the list): " + reason, "amber"))
            out.append(("", "text"))
        out.append(("REFERENCE", "cyan"))
        for l in wrap(REFERENCE, width):
            out.append((l, "dim" if not l.startswith("Rates") else "text"))
        out.append(("", "text"))
        out.append(("DENYLIST (destructive actions need the unit name typed)", "amber"))
        for pat, why in self.ex.policy.denylist:
            out += [(l, "dim") for l in wrap("%-30s %s" % (pat, why), width)]
        out.append(("", "text"))
        out.append(("MODE  %s   audit log: %s" % ("read-only" if self.ex.read_only else "dry-run" if self.ex.dry_run
                                                 else "LIVE", self.ex.audit.path or "disabled"), "text"))
        return out

    def draw_drawer(self, h, w):
        T = self.theme
        dw = max(50, min(80, w * 45 // 100))
        x, y, dh = w - dw, 1, h - 2
        self.cv.panel(y, x, dh, dw, T["text"])
        self.cv.box(y, x, dh, dw, T["border_focus"], "DETAILS / INFO", T["cyan"] | curses.A_BOLD,
                    "d/Esc close", T["dim"])
        lines = self.drawer_lines(dw - 4)
        body = dh - 2
        self.drawer_scroll = max(0, min(self.drawer_scroll, max(0, len(lines) - body)))
        for i, (t, k) in enumerate(lines[self.drawer_scroll: self.drawer_scroll + body]):
            self.cv.put(y + 1 + i, x + 2, t, T[k] | (curses.A_BOLD if k == "cyan" else 0), dw - 4)

    # ------------------------------------------------------------------ input
    def handle_key(self, ch) -> Optional[bool]:
        if self.filtering:
            return self._key_filter(ch)
        if self.overlay == "menu":
            return self._key_menu(ch)
        if self.overlay == "confirm":
            return self._key_confirm(ch)
        if self.overlay in ("drawer", "help"):
            if ch in (27, ord("q"), ord("d"), ord("?")) or (self.overlay == "help" and ch in (10, 13)):
                self.overlay = None
            elif self.overlay == "drawer" and ch in (curses.KEY_DOWN, ord("j")):
                self.drawer_scroll += 1
            elif self.overlay == "drawer" and ch in (curses.KEY_UP, ord("k")):
                self.drawer_scroll = max(0, self.drawer_scroll - 1)
            elif self.overlay == "drawer" and ch == curses.KEY_NPAGE:
                self.drawer_scroll += 10
            elif self.overlay == "drawer" and ch == curses.KEY_PPAGE:
                self.drawer_scroll = max(0, self.drawer_scroll - 10)
            return None
        if ch in (ord("q"), ord("Q")):
            return False
        if ch == 27:
            return None
        if ch == ord(" "):
            self.poller.paused = not self.poller.paused
            if not self.poller.paused:
                self.poller.kick()
            self.set_status("paused" if self.poller.paused else "resumed", "amber" if self.poller.paused else "green", 2)
        elif ch == ord("/"):
            self.filtering = True
        elif ch in (ord("r"), ord("R")):
            self.baseline = {s["unit"]: (s["in_bytes"] or 0) + (s["out_bytes"] or 0)
                             for s in self.snap["services"] if s["in_bytes"] is not None}
            self.sampler.reset_history()
            for s in self.snap["services"]:
                s["history"] = []
            self.set_status("stats reset (display baseline; kernel counters untouched)", "amber", 4)
        elif ch in (ord("+"), ord("=")):
            self._set_interval(min(self.poller.interval * 2, 10.0))
        elif ch == ord("-"):
            self._set_interval(max(self.poller.interval / 2, 0.25))
        elif ch in INTERVALS:
            self._set_interval(INTERVALS[ch])
        elif ch in (9, curses.KEY_BTAB):
            self.focus ^= 1
        elif ch in (curses.KEY_DOWN, ord("j")):
            self.move(1)
        elif ch in (curses.KEY_UP, ord("k")):
            self.move(-1)
        elif ch == curses.KEY_NPAGE:
            self.move(10)
        elif ch == curses.KEY_PPAGE:
            self.move(-10)
        elif ch in (curses.KEY_HOME, ord("g")):
            self.move(to=0)
        elif ch in (curses.KEY_END, ord("G")):
            self.move(to=10 ** 9)
        elif ch in (10, 13, curses.KEY_ENTER, ord("a")):
            self.open_menu()
        elif ch == ord("d"):
            self.overlay, self.drawer_scroll = "drawer", 0
        elif ch == ord("?"):
            self.overlay = "help"
        elif ch == ord("v"):
            self.view = (self.view + 1) % len(VIEWS)
        return None

    def _set_interval(self, v):
        self.poller.interval = v
        self.poller.kick()
        self.set_status("refresh every %gs" % v, "cyan", 2)

    def _key_filter(self, ch):
        if ch in (10, 13, curses.KEY_ENTER):
            self.filtering = False
        elif ch == 27:
            self.filtering, self.filter = False, ""
        elif ch in (curses.KEY_BACKSPACE, 127, 8):
            self.filter = self.filter[:-1]
        elif 32 <= ch < 127:
            self.filter += chr(ch)
        return None

    def _key_menu(self, ch):
        items = self.menu["items"]
        if ch in (27, ord("q")):
            self.overlay = None
        elif ch in (curses.KEY_DOWN, ord("j")):
            self.menu["idx"] = (self.menu["idx"] + 1) % len(items)
        elif ch in (curses.KEY_UP,):
            self.menu["idx"] = (self.menu["idx"] - 1) % len(items)
        elif ch in (10, 13, curses.KEY_ENTER):
            self.open_confirm(items[self.menu["idx"]])
        elif 32 < ch < 127:
            for it in items:
                if it["key"] == chr(ch):
                    self.open_confirm(it)
                    break
        return None

    def _key_confirm(self, ch):
        c = self.confirm
        p = c["preview"]
        if ch == 27:
            self.overlay = None
            self.set_status("cancelled", "dim", 3)
            return None
        if p["requires_force"]:
            if ch in (10, 13, curses.KEY_ENTER):
                want = c["unit"] if c["kind"] == "unit" else str(c["pid"])
                if c["typed"].strip() == want:
                    self.execute(force=True)
                else:
                    self.set_status("override text does not match %r" % want, "red", 4)
            elif ch in (curses.KEY_BACKSPACE, 127, 8):
                c["typed"] = c["typed"][:-1]
            elif 32 <= ch < 127:
                c["typed"] += chr(ch)
            return None
        if ch == ord(" ") and c["kind"] == "unit" and c["action"] in ("disable", "mask"):
            it = {k: v for k, v in c.items() if k not in ("preview", "typed")}
            it["now"] = not c["now"]
            self.open_confirm(it)
        elif ch in (10, 13, curses.KEY_ENTER, ord("y"), ord("Y")):
            self.execute(force=False)
        elif ch in (ord("n"), ord("N"), ord("q")):
            self.overlay = None
            self.set_status("cancelled", "dim", 3)
        return None

    def execute(self, force: bool):
        c = self.confirm
        self.overlay = None
        cmd = " ".join(shlex.quote(a) for a in c["preview"]["cmd"])
        self.set_status("running: " + cmd, "amber", 60)
        self.draw()
        try:
            if c["kind"] == "unit":
                res = self.ex.run_unit(c["action"], c["unit"], c.get("sig"), c.get("now", False), force, client="tui")
            else:
                res = self.ex.kill_pid(c["pid"], c["inode"], c["sig"], force, client="tui")
            kind = "amber" if res.get("dry_run") else ("green" if res["ok"] else "red")
            msg = ("DRY-RUN logged: " if res.get("dry_run") else ("OK: " if res["ok"] else "FAILED rc=%s: " % res.get("rc")))
            detail = "" if res["ok"] else " | " + (res.get("message") or "").strip().replace("\n", " ")
            self.set_status(msg + cmd + detail, kind, 10)
        except ActionError as e:
            self.set_status("refused: " + e.msg, "red", 10)
        self.sampler.invalidate()
        self.poller.kick()
