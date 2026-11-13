#!/usr/bin/env python3
"""netmon-win: the systemd-netmon live page, ported to Windows. READ-ONLY.

Python 3 stdlib only. Polls two native helpers and serves the original page on 127.0.0.1:

  * helpers/netmon-etw.exe (C#, ETW kernel TCP/IP): per-service bytes in/out, service list
  * helpers/netmon-raw.exe (C++): Npcap/WinPcap users, raw-socket hints, WFP filters/callouts

Run from an elevated prompt (Administrator) for ETW bytes and WFP:

    python netmon_win.py            (or netmon-win.exe when packaged with PyInstaller)
    open https://e-sentry.net/      (the hosted dashboard reads http://127.0.0.1:8787/api/data)

Graceful degradation: without the ETW helper (or without admin) the service list comes from
`sc queryex` + `tasklist /svc`, connection counts per PID from `netstat -ano`, and byte
columns show n/a. Without netmon-raw.exe the bottom panel says so.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import os
import platform
import re
import subprocess
import sys
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

VERSION = "1.4.0-win"
IS_WINDOWS = os.name == "nt"
FROZEN = getattr(sys, "frozen", False)
HERE = os.path.dirname(os.path.abspath(sys.executable if FROZEN else __file__))
BUNDLE = getattr(sys, "_MEIPASS", HERE)  # PyInstaller one-file extraction dir
NO_WINDOW = 0x08000000 if IS_WINDOWS else 0  # CREATE_NO_WINDOW


# ------------------------------------------------------------------ environment
def is_admin() -> bool:
    if not IS_WINDOWS:
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def windows_label(values: dict | None = None) -> str:
    """'Windows 11 Pro 24H2 / build 26100.2314' from the CurrentVersion registry key.
    ProductName still says 'Windows 10' on Windows 11, so the build number decides."""
    v = values
    if v is None:
        if not IS_WINDOWS:
            return "%s %s (not Windows)" % (platform.system(), platform.release())
        v = {}
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as k:
                for name in ("ProductName", "DisplayVersion", "ReleaseId", "CurrentBuild", "UBR", "EditionID"):
                    try:
                        v[name] = winreg.QueryValueEx(k, name)[0]
                    except OSError:
                        pass
        except OSError:
            return "Windows %s" % platform.version()
    name = str(v.get("ProductName") or "Windows")
    try:
        build = int(str(v.get("CurrentBuild", "0")))
    except ValueError:
        build = 0
    if build >= 22000 and name.startswith("Windows 10"):
        name = "Windows 11" + name[len("Windows 10"):]
    rel = v.get("DisplayVersion") or v.get("ReleaseId") or ""
    b = str(build) + ("." + str(v["UBR"]) if v.get("UBR") not in (None, "") else "")
    return ("%s %s / build %s" % (name, rel, b)).replace("  ", " ")


def find_helper(name: str, explicit: str | None = None) -> str | None:
    if explicit:
        return explicit if os.path.isfile(explicit) else None
    for d in (os.path.join(HERE, "helpers"), os.path.join(HERE, "bin"), HERE,
              os.path.join(BUNDLE, "helpers"), BUNDLE):
        p = os.path.join(d, name)
        if os.path.isfile(p):
            return p
    return None


def run_cmd(cmd, timeout=20):
    """(rc, stdout, stderr); console tools print in the OEM code page."""
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout, creationflags=NO_WINDOW,
                           stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError) as e:
        return 127, "", str(e)
    enc = "oem" if IS_WINDOWS else "utf-8"
    return p.returncode, p.stdout.decode(enc, "replace"), p.stderr.decode(enc, "replace")


# ------------------------------------------------------------------ fallback parsers (no ETW)
SC_STATES = {1: "stopped", 2: "start_pending", 3: "stop_pending", 4: "running",
             5: "continue_pending", 6: "pause_pending", 7: "paused"}


def parse_sc_queryex(text: str) -> list[dict]:
    """`sc queryex type= service state= all`. Keys are not localised; values after ':' are."""
    out, cur = [], None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or ":" not in line:
            continue
        key, _, val = line.partition(":")
        key, val = key.strip().upper(), val.strip()
        if key == "SERVICE_NAME":
            cur = {"name": val, "displayName": val, "state": "unknown", "pid": 0, "shared": False}
            out.append(cur)
        elif cur is None:
            continue
        elif key == "DISPLAY_NAME":
            cur["displayName"] = val
        elif key == "STATE":
            m = re.match(r"(\d+)", val)
            if m:
                cur["state"] = SC_STATES.get(int(m.group(1)), "unknown")
        elif key == "TYPE":
            m = re.match(r"([0-9a-fA-F]+)", val)
            if m:
                cur["shared"] = bool(int(m.group(1), 16) & 0x20)
        elif key == "PID":
            m = re.match(r"(\d+)", val)
            cur["pid"] = int(m.group(1)) if m else 0
    return out


def parse_tasklist_svc(text: str) -> dict[int, dict]:
    """`tasklist /svc /fo csv /nh` -> {pid: {"image": str, "services": [..]}}."""
    out = {}
    for row in csv.reader(io.StringIO(text)):
        if len(row) < 3:
            continue
        try:
            pid = int(row[1])
        except ValueError:
            continue
        svcs = [s.strip() for s in row[2].split(",") if s.strip() and s.strip().upper() != "N/A"]
        out[pid] = {"image": row[0], "services": svcs}
    return out


def parse_netstat_ano(text: str) -> dict[int, dict]:
    """`netstat -ano` -> {pid: {"tcp": n, "udp": n, "listen": n}}. State words are localised,
    so 'listening' is detected from a zero remote address instead."""
    out: dict[int, dict] = {}
    for line in text.splitlines():
        f = line.split()
        if len(f) < 4 or f[0].upper() not in ("TCP", "UDP"):
            continue
        try:
            pid = int(f[-1])
        except ValueError:
            continue
        d = out.setdefault(pid, {"tcp": 0, "udp": 0, "listen": 0})
        if f[0].upper() == "TCP":
            d["tcp"] += 1
            if len(f) >= 5 and f[2] in ("0.0.0.0:0", "[::]:0"):
                d["listen"] += 1
        else:
            d["udp"] += 1
    return out


def groups_from_fallback(svcs: list[dict], tasks: dict[int, dict]) -> tuple[list[dict], list[dict]]:
    """Build the same 'services'/'groups' structure netmon-etw emits, bytes = None."""
    by_pid: dict[int, list[str]] = {}
    for s in svcs:
        if s["state"] != "stopped" and s.get("pid"):
            by_pid.setdefault(s["pid"], []).append(s["name"])
    for pid, t in tasks.items():  # tasklist knows services sc could not report a PID for
        for name in t["services"]:
            if name not in by_pid.get(pid, []) and not any(name in v for v in by_pid.values()):
                by_pid.setdefault(pid, []).append(name)
    groups = []
    for pid in sorted(by_pid):
        names = sorted(by_pid[pid], key=str.lower)
        groups.append({"id": "pid:%d" % pid, "pid": pid, "process": tasks.get(pid, {}).get("image", "pid %d" % pid),
                       "services": names, "attribution": "exclusive" if len(names) == 1 else "shared-process",
                       "inBytes": None, "outBytes": None})
    rows = [{"name": s["name"], "displayName": s["displayName"], "state": s["state"], "startType": "unknown",
             "pid": s["pid"], "group": ("pid:%d" % s["pid"]) if s.get("pid") and s["state"] != "stopped" else None}
            for s in svcs]
    return groups, rows


# ------------------------------------------------------------------ helper feeds
class EtwFeed:
    """Long-running netmon-etw.exe; reads JSON lines from its stdout on a thread."""

    def __init__(self, cmd: list[str] | None, interval_ms=1000, popen=subprocess.Popen, clock=time.monotonic):
        self.cmd, self.interval_ms, self.popen, self.clock = cmd, interval_ms, popen, clock
        self.latest: dict | None = None
        self.latest_at = 0.0
        self.status = "missing" if not cmd else "stopped"
        self.error: str | None = None if cmd else "netmon-etw.exe not found"
        self.stderr_tail: deque[str] = deque(maxlen=5)
        self.proc = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None

    def start(self):
        if not self.cmd or self._thread:
            return
        self._thread = threading.Thread(target=self._run, name="etw-feed", daemon=True)
        self._thread.start()

    def _run(self):
        backoff = 2.0
        while not self._stop.is_set():
            self.status = "starting"
            try:
                self.proc = self.popen(self.cmd + ["--interval-ms", str(self.interval_ms), "--exit-on-stdin-eof"],
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       creationflags=NO_WINDOW)
            except OSError as e:
                self.status, self.error = "error", "cannot start netmon-etw: %s" % e
                if self._stop.wait(backoff):
                    return
                backoff = min(backoff * 2, 60)
                continue
            threading.Thread(target=self._drain_stderr, args=(self.proc,), daemon=True).start()
            for raw in self.proc.stdout:
                try:
                    snap = json.loads(raw.decode("utf-8", "replace"))
                except ValueError:
                    continue
                if snap.get("schema") != "netmon-etw/1":
                    continue
                with self._lock:
                    self.latest, self.latest_at = snap, self.clock()
                self.status, self.error, backoff = "running", None, 2.0
            rc = self.proc.wait()
            if self._stop.is_set():
                return
            tail = " | ".join(self.stderr_tail)
            self.status, self.error = "exited", "netmon-etw exited (code %s)%s" % (rc, ": " + tail if tail else "")
            if self._stop.wait(backoff):
                return
            backoff = min(backoff * 2, 60)

    def _drain_stderr(self, proc):
        for raw in proc.stderr:
            line = raw.decode("utf-8", "replace").strip()
            if line:
                self.stderr_tail.append(line[:300])

    def snapshot(self) -> dict | None:
        with self._lock:
            if self.latest is None:
                return None
            if self.clock() - self.latest_at > max(5.0, 5 * self.interval_ms / 1000.0):
                self.status = "stale"
                return None
            return self.latest

    def stop(self):
        self._stop.set()
        p = self.proc
        if p and p.poll() is None:
            try:
                p.stdin.close()  # helper sees EOF and disposes its ETW session cleanly
                p.wait(timeout=5)
            except Exception:
                p.kill()  # only our own child


class RawFeed:
    """Runs netmon-raw.exe every `period` seconds (WFP enumeration is not free)."""

    def __init__(self, cmd: list[str] | None, period=15.0, runner=run_cmd, clock=time.monotonic):
        self.cmd, self.period, self.runner, self.clock = cmd, period, runner, clock
        self.latest: dict | None = None
        self.error: str | None = None if cmd else "netmon-raw.exe not found"
        self.status = "missing" if not cmd else "stopped"
        self._stop = threading.Event()
        self._thread = None

    def poll_once(self):
        rc, out, err = self.runner(self.cmd, 90)
        try:
            data = json.loads(out)
            if data.get("schema") != "netmon-raw/1":
                raise ValueError("unexpected schema")
            self.latest, self.error, self.status = data, None, "ok"
        except ValueError:
            self.status = "error"
            self.error = "netmon-raw failed (code %s): %s" % (rc, (err or out).strip()[:300])

    def start(self):
        if not self.cmd or self._thread:
            return

        def loop():
            while not self._stop.is_set():
                self.poll_once()
                self._stop.wait(self.period)
        self._thread = threading.Thread(target=loop, name="raw-feed", daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()


class FallbackFeed:
    """sc queryex + tasklist /svc + netstat -ano, cached for `period` seconds."""

    def __init__(self, runner=run_cmd, period=5.0, clock=time.monotonic):
        self.runner, self.period, self.clock = runner, period, clock
        self._svc_at = self._net_at = -1e9
        self.services: list[dict] = []
        self.tasks: dict[int, dict] = {}
        self.conns: dict[int, dict] | None = None
        self.error: str | None = None
        self._lock = threading.Lock()

    def service_data(self):
        with self._lock:
            now = self.clock()
            if now - self._svc_at >= self.period:
                self._svc_at = now
                rc, out, err = self.runner(["sc", "queryex", "type=", "service", "state=", "all"], 30)
                svcs = parse_sc_queryex(out) if rc == 0 else []
                rc2, out2, err2 = self.runner(["tasklist", "/svc", "/fo", "csv", "/nh"], 30)
                tasks = parse_tasklist_svc(out2) if rc2 == 0 else {}
                self.services, self.tasks = svcs, tasks
                self.error = None if (svcs or tasks) else "fallback failed: sc (%s) / tasklist (%s) %s" % (
                    rc, rc2, (err or err2).strip()[:200])
            return self.services, self.tasks

    def connections(self):
        with self._lock:
            now = self.clock()
            if now - self._net_at >= self.period:
                self._net_at = now
                rc, out, _ = self.runner(["netstat", "-ano"], 30)
                self.conns = parse_netstat_ano(out) if rc == 0 else None
            return self.conns


# ------------------------------------------------------------------ bottom panel rows
def capture_rows(raw: dict | None) -> tuple[list[dict], dict]:
    """netmon-raw JSON -> rows for the CAPTURE / RAW / WFP panel + counts for the header."""
    rows: list[dict] = []
    counts = {"capture": None, "raw": None, "wfpFilters": None, "wfpCallouts": None}
    if not raw:
        return rows, counts
    cap = raw.get("capture") or {}
    drv = cap.get("drivers") or {}
    adapters = cap.get("adapters") or {}
    n_adapters = len(adapters.get("list") or []) if isinstance(adapters.get("list"), list) else None
    for key, label in (("npcap", "Npcap driver"), ("winpcap", "WinPcap driver")):
        d = drv.get(key) or {}
        if d.get("state") and d.get("state") != "missing":
            rows.append({"kind": "driver", "procName": label, "pid": None, "proto": "service %s" % d.get("service", key),
                         "detail": d.get("state"),
                         "count": ("%d adapters" % n_adapters) if (key == "npcap" and n_adapters is not None) else "n/a"})
    procs: dict[int, dict] = {}
    ms = cap.get("moduleScan") or {}
    for p in ms.get("processes") or []:
        mods = [m.get("name", "") for m in p.get("modules") or []]
        paths = " ".join(m.get("path", "") for m in p.get("modules") or []).lower()
        flavour = "Npcap" if "\\npcap\\" in paths else ("WinPcap" if paths else "?")
        procs[p["pid"]] = {"kind": "capture", "procName": p.get("process") or "pid %s" % p["pid"], "pid": p["pid"],
                           "proto": "%s (%s)" % (", ".join(sorted(set(mods))), flavour), "detail": "module",
                           "count": "%d module%s" % (len(mods), "" if len(mods) == 1 else "s")}
    hs = cap.get("handleScan") or {}
    for p in hs.get("processes") or []:
        devs = p.get("devices") or []
        r = procs.get(p["pid"])
        if r:
            r["detail"] = "module+handle"
            r["count"] += ", %d device%s" % (len(devs), "" if len(devs) == 1 else "s")
        else:
            procs[p["pid"]] = {"kind": "capture", "procName": p.get("process") or "pid %s" % p["pid"], "pid": p["pid"],
                               "proto": devs[0] if devs else "capture device", "detail": "handle",
                               "count": "%d device%s" % (len(devs), "" if len(devs) == 1 else "s")}
    rows.extend(sorted(procs.values(), key=lambda r: (str(r["procName"]).lower(), r["pid"])))
    counts["capture"] = len(procs) if (ms.get("processes") is not None or hs.get("processes") is not None) else None
    rs = raw.get("rawSockets") or {}
    owners = rs.get("legacyHandleOwners") or []
    for o in owners:
        rows.append({"kind": "raw", "procName": o.get("process"), "pid": o.get("pid"), "proto": o.get("device"),
                     "detail": "legacy RawIp", "count": "handle"})
    counts["raw"] = len(owners) if hs.get("enabled") else None
    wfp = raw.get("wfp") or {}
    if wfp.get("available"):
        counts["wfpFilters"] = wfp.get("filterCount")
        counts["wfpCallouts"] = wfp.get("calloutCount")
        for g in wfp.get("summary") or []:
            rows.append({"kind": "wfp", "procName": g.get("provider"), "pid": None, "proto": g.get("layer"),
                         "detail": g.get("action"), "count": "%s filter%s" % (g.get("count"), "" if g.get("count") == 1 else "s"),
                         "title": "; ".join(g.get("sampleNames") or [])})
        per_prov: dict[str, list[str]] = {}
        for c in wfp.get("callouts") or []:
            per_prov.setdefault(c.get("provider") or "(no provider)", []).append(c.get("name") or "")
        for prov, names in sorted(per_prov.items(), key=lambda kv: (-len(kv[1]), kv[0].lower())):
            rows.append({"kind": "callout", "procName": prov, "pid": None, "proto": "callouts", "detail": "callout",
                         "count": "%d callout%s" % (len(names), "" if len(names) == 1 else "s"),
                         "title": "; ".join(names[:10])})
    return rows, counts


# ------------------------------------------------------------------ sampler
class Sampler:
    def __init__(self, etw: EtwFeed, raw: RawFeed, fallback: FallbackFeed, clock=time.monotonic,
                 os_label: str | None = None, admin: bool | None = None, min_interval=0.25):
        self.etw, self.raw, self.fallback, self.clock = etw, raw, fallback, clock
        self.os_label = os_label or windows_label()
        self.admin = is_admin() if admin is None else admin
        self.min_interval = min_interval
        self.prev: dict[str, tuple] = {}
        self.history: dict[str, deque] = {}
        self.cache, self.cache_ts = None, -1e9
        self.lock = threading.Lock()

    @staticmethod
    def rate(cur, prev, dt):
        if cur is None or prev is None or dt <= 0 or cur < prev:
            return None  # n/a, first sample, or counter restart (helper restarted / PID reused)
        return (cur - prev) / dt

    def sample(self) -> dict:
        with self.lock:
            now = self.clock()
            if self.cache is not None and now - self.cache_ts < self.min_interval:
                return self.cache
            self.cache, self.cache_ts = self._build(now), now
            return self.cache

    def _build(self, now) -> dict:
        banner: list[str] = []
        snap = self.etw.snapshot()
        etw_bytes = bool(snap and (snap.get("etw") or {}).get("active"))
        if snap:
            groups, rows, mode = snap.get("groups") or [], snap.get("services") or [], "etw" if etw_bytes else "etw-services"
            if not etw_bytes:
                banner.append("ETW byte counters off: %s" % ((snap.get("etw") or {}).get("error") or "unknown reason"))
            if snap.get("scmError"):
                banner.append("SCM: %s" % snap["scmError"])
        else:
            svcs, tasks = self.fallback.service_data()
            groups, rows = groups_from_fallback(svcs, tasks)
            mode = "fallback"
            banner.append("FALLBACK MODE (sc / tasklist / netstat): %s" % (self.etw.error or "netmon-etw %s" % self.etw.status))
            if self.fallback.error:
                banner.append(self.fallback.error)
        if not self.admin:
            banner.append("Not running as Administrator: ETW bytes and WFP filters need an elevated prompt")
        conns = None if etw_bytes else self.fallback.connections()

        by_name = {r["name"]: r for r in rows}
        services, tin, tout, monitored = [], 0.0, 0.0, 0
        for g in groups:
            members = g.get("services") or []
            key = g["id"]
            ib, ob = g.get("inBytes"), g.get("outBytes")
            p = self.prev.get(key)
            dt = now - p[0] if p else 0
            ir = self.rate(ib, p[1] if p else None, dt)
            er = self.rate(ob, p[2] if p else None, dt)
            self.prev[key] = (now, ib, ob)
            if ir is not None or er is not None:
                self.history.setdefault(key, deque(maxlen=60)).append(((ir or 0) + (er or 0)) / 1024.0)
            mon = ib is not None
            monitored += len(members) if mon else 0
            tin += ir or 0
            tout += er or 0
            first = by_name.get(members[0], {}) if members else {}
            name = members[0] if len(members) == 1 else "%s +%d" % (members[0] if members else "?", max(0, len(members) - 1))
            c = (conns or {}).get(g["pid"]) if conns is not None else None
            desc = "%s (PID %s)" % (g.get("process", ""), g["pid"])
            if len(members) > 1:
                desc += " shared by: " + ", ".join(members) + ". Bytes are for the whole process (not split)."
            elif first.get("displayName"):
                desc = "%s; %s, start: %s" % (first["displayName"], desc, first.get("startType", "unknown"))
            services.append({
                "name": name, "id": key, "members": members, "description": desc, "pid": g["pid"],
                "process": g.get("process"), "attribution": g.get("attribution"),
                "displayName": first.get("displayName", ""), "startType": first.get("startType", "unknown"),
                "activeState": "active", "monitored": mon, "ingress": ib, "egress": ob,
                "ingressRate": ir, "egressRate": er, "history": list(self.history.get(key, ())),
                "connections": None if c is None and conns is None else (c or {"tcp": 0, "udp": 0, "listen": 0}),
            })
        live = {g["id"] for g in groups}
        for k in list(self.prev):  # forget vanished processes
            if k not in live:
                self.prev.pop(k, None)
                self.history.pop(k, None)

        running = sum(1 for r in rows if r.get("state") == "running")
        sockets, counts = capture_rows(self.raw.latest)
        if self.raw.error:
            banner.append(self.raw.error)
        non = (snap or {}).get("nonService") if etw_bytes else None
        return {
            "version": VERSION, "ts": time.time(), "os": self.os_label, "host": platform.node(),
            "is_admin": self.admin, "mode": mode, "banner": banner,
            "helpers": {"etw": {"status": self.etw.status, "error": self.etw.error,
                                "etw": (snap or {}).get("etw")},
                        "raw": {"status": self.raw.status, "error": self.raw.error}},
            "services": services, "servicesAll": len(rows),
            "sockets": sockets,
            "rawSocketsNote": ((self.raw.latest or {}).get("rawSockets") or {}).get("note"),
            "totals": {"ingressRate": tin, "egressRate": tout, "running": running, "monitored": monitored,
                       "sockets": len(sockets), "capture": counts["capture"], "raw": counts["raw"],
                       "wfpFilters": counts["wfpFilters"], "wfpCallouts": counts["wfpCallouts"],
                       "nonServiceIn": (non or {}).get("inBytes"), "nonServiceOut": (non or {}).get("outBytes")},
        }


# Origins whose pages may read /api/data cross-origin (the hosted dashboard on GitHub Pages,
# shown through the e-sentry.net frame). Exact match only; add more with --allow-origin.
HOSTED_URL = "https://e-sentry.net/"
DEFAULT_ALLOWED_ORIGINS = ("https://dansun32.github.io", "https://e-sentry.net", "https://www.e-sentry.net")
_ORIGIN_RE = re.compile(r"^https?://[A-Za-z0-9.-]+(?::\d{1,5})?$")
_SAFE_REQ_HEADERS = {"accept", "accept-language", "content-language", "cache-control", "pragma"}


def check_origin(value: str) -> str:
    """argparse type for --allow-origin: scheme://host[:port], no path, no wildcard."""
    v = value.strip().rstrip("/")
    if not _ORIGIN_RE.match(v):
        raise argparse.ArgumentTypeError("origin must look like https://example.com[:port] (no path, no '*')")
    return v.lower()


# ------------------------------------------------------------------ HTTP (same rules as the live helper)
class Handler(BaseHTTPRequestHandler):
    sampler: Sampler = None  # type: ignore
    page_path = os.path.join(BUNDLE, "netmon.html")
    server_version = "netmon-win"
    sys_version = ""
    allowed_origins = frozenset(DEFAULT_ALLOWED_ORIGINS)

    def log_request(self, code="-", size="-"):
        if str(getattr(code, "value", code))[:1] in ("4", "5"):
            super().log_request(code, size)

    def send(self, status, body, ctype, extra=()):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        for k, v in extra:  # CORS headers, only ever for GET/OPTIONS /api/data from an allowed origin
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def host_ok(self):
        port = self.server.server_address[1]
        return self.headers.get("Host", "") in {"127.0.0.1:%d" % port, "localhost:%d" % port}

    def origin_state(self):
        """('none'|'self'|'allowed'|'denied', origin). Same-origin = the helper's own page."""
        origin = self.headers.get("Origin")
        if origin is None:
            return "none", None
        port = self.server.server_address[1]
        if origin in ("http://127.0.0.1:%d" % port, "http://localhost:%d" % port):
            return "self", origin
        if origin in self.allowed_origins:
            return "allowed", origin
        return "denied", origin

    @staticmethod
    def cors_headers(origin):
        return [("Access-Control-Allow-Origin", origin), ("Vary", "Origin")]

    def do_OPTIONS(self):  # CORS preflight, /api/data only, allowed origins only
        if not self.host_ok():
            return self.send(421, b'{"error":"bad Host header"}', "application/json")
        state, origin = self.origin_state()
        if urlsplit(self.path).path != "/api/data" or state != "allowed":
            return self.send(403 if state == "denied" else 405, b'{"error":"read-only"}', "application/json",
                             [("Vary", "Origin")])
        if self.headers.get("Access-Control-Request-Method", "GET").upper() not in ("GET", "HEAD"):
            return self.send(403, b'{"error":"read-only"}', "application/json", [("Vary", "Origin")])
        extra = self.cors_headers(origin) + [("Access-Control-Allow-Methods", "GET"),
                                             ("Access-Control-Max-Age", "600")]
        req_h = [h.strip().lower() for h in self.headers.get("Access-Control-Request-Headers", "").split(",") if h.strip()]
        if req_h:
            if any(h not in _SAFE_REQ_HEADERS for h in req_h):
                return self.send(403, b'{"error":"header not allowed"}', "application/json", [("Vary", "Origin")])
            extra.append(("Access-Control-Allow-Headers", ", ".join(req_h)))
        # Chrome Private/Local Network Access preflights (public site -> 127.0.0.1)
        if self.headers.get("Access-Control-Request-Private-Network", "").lower() == "true":
            extra.append(("Access-Control-Allow-Private-Network", "true"))
        if self.headers.get("Access-Control-Request-Local-Network", "").lower() == "true":
            extra.append(("Access-Control-Allow-Local-Network", "true"))
        return self.send(204, b"", "text/plain", extra)

    def do_GET(self):
        if not self.host_ok():  # DNS-rebinding protection
            return self.send(421, b'{"error":"bad Host header"}', "application/json")
        path = urlsplit(self.path).path
        state, origin = self.origin_state()  # other sites get no CORS headers, so their pages cannot read the reply
        if path == "/favicon.ico":
            return self.send(204, b"", "image/x-icon")
        if path in ("/", "/index.html", "/netmon.html"):
            try:
                with open(self.page_path, "rb") as fh:
                    return self.send(200, fh.read(), "text/html; charset=utf-8")
            except OSError:
                return self.send(500, b"netmon.html missing next to netmon_win.py", "text/plain")
        if path == "/api/data":
            extra = self.cors_headers(origin) if state == "allowed" else [("Vary", "Origin")]
            try:
                data = self.sampler.sample()
            except Exception as e:
                return self.send(500, json.dumps({"error": "%s: %s" % (type(e).__name__, e)}).encode(), "application/json")
            return self.send(200, json.dumps(data).encode(), "application/json", extra)
        return self.send(404, b'{"error":"not found"}', "application/json")

    do_HEAD = do_GET

    def do_POST(self):  # read-only
        self.send(405, b'{"error":"read-only"}', "application/json")

    do_PUT = do_DELETE = do_PATCH = do_POST  # never CORS


def make_server(sampler, port=8787, extra_origins=()):
    allowed = frozenset(DEFAULT_ALLOWED_ORIGINS) | frozenset(extra_origins)
    handler = type("H", (Handler,), {"sampler": sampler, "allowed_origins": allowed})
    srv = ThreadingHTTPServer(("127.0.0.1", port), handler)
    srv.daemon_threads = True
    return srv


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=8787, help="port on 127.0.0.1 (default 8787)")
    ap.add_argument("--allow-origin", action="append", default=[], type=check_origin, metavar="ORIGIN",
                    help="extra site allowed to read /api/data (repeatable); built in: " + ", ".join(DEFAULT_ALLOWED_ORIGINS))
    ap.add_argument("--interval", type=float, default=1.0, help="ETW snapshot period in seconds (default 1.0)")
    ap.add_argument("--raw-period", type=float, default=15.0, help="seconds between netmon-raw runs (default 15)")
    ap.add_argument("--etw-exe", help="path to netmon-etw.exe (default: helpers/ next to this file)")
    ap.add_argument("--raw-exe", help="path to netmon-raw.exe")
    ap.add_argument("--handles", action="store_true", help="let netmon-raw do the optional handle scan")
    ap.add_argument("--no-wfp", action="store_true", help="skip WFP enumeration")
    ap.add_argument("--fallback", action="store_true", help="ignore the ETW helper (sc/tasklist/netstat only)")
    ap.add_argument("--open", action="store_true", help="open the hosted dashboard (%s) in the default browser" % HOSTED_URL)
    ap.add_argument("--open-local", action="store_true", help="open the copy served by this helper (http://127.0.0.1:PORT/) instead")
    a = ap.parse_args(argv)
    if not IS_WINDOWS:
        print("WARNING: not Windows; helpers and fallback commands will not work here.", file=sys.stderr)
    etw_exe = None if a.fallback else find_helper("netmon-etw.exe", a.etw_exe)
    raw_exe = find_helper("netmon-raw.exe", a.raw_exe)
    raw_cmd = [raw_exe] + (["--handles"] if a.handles else []) + (["--no-wfp"] if a.no_wfp else []) if raw_exe else None
    etw = EtwFeed([etw_exe] if etw_exe else None, interval_ms=int(max(0.25, min(60, a.interval)) * 1000))
    if a.fallback:
        etw.error = "disabled with --fallback"
    raw = RawFeed(raw_cmd, period=max(2.0, a.raw_period))
    sampler = Sampler(etw, raw, FallbackFeed())
    srv = make_server(sampler, a.port, a.allow_origin)
    if not sampler.admin:
        print("NOTE: not elevated: run from an Administrator prompt for ETW bytes and WFP filters.", file=sys.stderr)
    for n, p in (("netmon-etw.exe", etw_exe), ("netmon-raw.exe", raw_exe)):
        print("%-15s %s" % (n, p or "NOT FOUND (degraded)"), file=sys.stderr)
    etw.start()
    raw.start()
    url = "http://127.0.0.1:%d/" % srv.server_address[1]
    print("netmon-win (read-only) on %s  (Ctrl-C to stop)" % url, flush=True)
    print("Live data for the hosted dashboard: open %s" % HOSTED_URL, flush=True)
    if a.open or a.open_local:
        import webbrowser
        webbrowser.open(url if a.open_local else HOSTED_URL)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        etw.stop()
        raw.stop()
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
