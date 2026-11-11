"""systemd data collection by shelling out to `systemctl` (no D-Bus bindings needed).

Why systemctl instead of dbus-python/dbus-next/pydbus: zero pip dependencies,
identical semantics to what the user would type, works for root and non-root,
and `systemctl show` returns every property we need in one call for many units.
"""
from __future__ import annotations

import os
import subprocess
import threading
import time
from collections import deque
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from . import procnet

UINT64_MAX = 2 ** 64 - 1
SHOW_PROPS = [
    "Id", "Description", "LoadState", "ActiveState", "SubState", "UnitFileState",
    "MainPID", "IPAccounting", "IPIngressBytes", "IPEgressBytes",
    "IPIngressPackets", "IPEgressPackets",
]

Runner = Callable[[Sequence[str], float], Tuple[int, str, str]]


def default_runner(cmd: Sequence[str], timeout: float = 20.0) -> Tuple[int, str, str]:
    env = dict(os.environ, LC_ALL="C", SYSTEMD_PAGER="", SYSTEMD_COLORS="0")
    try:
        p = subprocess.run(list(cmd), capture_output=True, text=True, timeout=timeout, env=env)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError as e:
        return 127, "", str(e)
    except subprocess.TimeoutExpired:
        return 124, "", "timeout after %ss" % timeout


def systemd_available() -> bool:
    """Same test as sd_booted(3)."""
    return os.path.isdir("/run/systemd/system")


def parse_counter(v: Optional[str]) -> Optional[int]:
    """systemd prints '[not set]' (v>=24x) or UINT64_MAX (older) when accounting is off."""
    if v is None:
        return None
    v = v.strip()
    if not v.isdigit():
        return None
    n = int(v)
    return None if n >= UINT64_MAX else n


def parse_show(text: str) -> List[Dict[str, str]]:
    """Parse `systemctl show -p ... unit1 unit2 ...` output (blank-line separated blocks)."""
    blocks, cur = [], {}
    for line in text.splitlines():
        if not line.strip():
            if cur:
                blocks.append(cur)
                cur = {}
            continue
        if "=" in line:
            k, v = line.split("=", 1)
            cur[k] = v
    if cur:
        blocks.append(cur)
    return blocks


def parse_list_units(text: str) -> List[Dict[str, str]]:
    """Parse `systemctl list-units --plain --no-legend` (UNIT LOAD ACTIVE SUB DESCRIPTION)."""
    out = []
    for line in text.splitlines():
        line = line.strip().lstrip("\u25cf*").strip()
        if not line:
            continue
        f = line.split(None, 4)
        if len(f) < 4:
            continue
        out.append({"unit": f[0], "load": f[1], "active": f[2], "sub": f[3],
                    "description": f[4] if len(f) > 4 else ""})
    return out


def parse_list_unit_files(text: str) -> List[Dict[str, str]]:
    out = []
    for line in text.splitlines():
        f = line.split()
        if len(f) >= 2 and "." in f[0]:
            out.append({"unit": f[0], "state": f[1]})
    return out


def unit_record(props: Dict[str, str]) -> dict:
    return {
        "unit": props.get("Id", ""),
        "description": props.get("Description", ""),
        "load_state": props.get("LoadState", ""),
        "active_state": props.get("ActiveState", ""),
        "sub_state": props.get("SubState", ""),
        "unit_file_state": props.get("UnitFileState", "") or "-",
        "main_pid": int(props["MainPID"]) if props.get("MainPID", "").isdigit() else 0,
        "ip_accounting": props.get("IPAccounting", "no") == "yes",
        "in_bytes": parse_counter(props.get("IPIngressBytes")),
        "out_bytes": parse_counter(props.get("IPEgressBytes")),
        "in_packets": parse_counter(props.get("IPIngressPackets")),
        "out_packets": parse_counter(props.get("IPEgressPackets")),
    }


def list_service_units(runner: Runner) -> Tuple[List[str], Optional[str]]:
    rc, out, err = runner(["systemctl", "list-units", "--type=service", "--all",
                           "--plain", "--no-legend", "--no-pager"], 20)
    if rc != 0:
        return [], (err or out).strip() or "systemctl list-units failed (rc=%d)" % rc
    names = [u["unit"] for u in parse_list_units(out) if u["load"] != "not-found"]
    # masked units are often not loaded -> include them so they can be unmasked
    rc2, out2, _ = runner(["systemctl", "list-unit-files", "--type=service",
                           "--state=masked", "--no-legend", "--no-pager"], 20)
    if rc2 == 0:
        for u in parse_list_unit_files(out2):
            if u["unit"] not in names and "@." not in u["unit"]:
                names.append(u["unit"])
    return names, None


def show_units(runner: Runner, units: List[str], chunk: int = 120) -> List[dict]:
    recs = []
    for i in range(0, len(units), chunk):
        part = units[i:i + chunk]
        rc, out, _ = runner(["systemctl", "show", "--no-pager", "-p", ",".join(SHOW_PROPS), "--"]
                            + part, 20)
        if rc not in (0, 1) and not out:
            continue
        recs.extend(unit_record(b) for b in parse_show(out) if b.get("Id"))
    return recs


class Sampler:
    """Thread-safe sampler; computes per-unit byte/packet rates between polls."""

    def __init__(self, runner: Runner = default_runner, min_interval: float = 0.3,
                 unit_list_ttl: float = 5.0, proc: str = procnet.PROC,
                 clock: Callable[[], float] = time.monotonic,
                 have_systemd: Optional[bool] = None):
        self.runner = runner
        self.min_interval = min_interval
        self.unit_list_ttl = unit_list_ttl
        self.proc = proc
        self.clock = clock
        self.have_systemd = systemd_available() if have_systemd is None else have_systemd
        self._lock = threading.Lock()
        self._prev: Dict[str, Tuple[float, dict]] = {}
        self._prev_sock: Dict[Tuple[str, int], Tuple[float, Optional[int]]] = {}
        self._units: List[str] = []
        self._units_ts = -1e9
        self._cache: Optional[dict] = None
        self._cache_ts = -1e9
        self.history: Dict[str, deque] = {}

    def reset_history(self):
        with self._lock:
            self.history.clear()

    def invalidate(self):
        with self._lock:
            self._units_ts = -1e9
            self._cache_ts = -1e9

    @staticmethod
    def _rate(cur, prev, dt):
        if cur is None or prev is None or dt <= 0 or cur < prev:
            return None  # n/a, or counter reset (unit restarted)
        return (cur - prev) / dt

    def sample(self) -> dict:
        with self._lock:
            now = self.clock()
            if self._cache is not None and now - self._cache_ts < self.min_interval:
                return self._cache
            snap = self._sample_locked(now)
            self._cache, self._cache_ts = snap, now
            return snap

    def _sample_locked(self, now: float) -> dict:
        services, err = [], None
        if self.have_systemd:
            if now - self._units_ts > self.unit_list_ttl or not self._units:
                names, err = list_service_units(self.runner)
                if not err:
                    self._units, self._units_ts = names, now
            services = show_units(self.runner, self._units) if self._units else []
        else:
            err = "systemd is not PID 1 / not running here (/run/systemd/system missing)"

        tot_in = tot_out = 0.0
        acct = 0
        for s in services:
            prev = self._prev.get(s["unit"])
            dt = now - prev[0] if prev else 0
            p = prev[1] if prev else {}
            for key in ("in_bytes", "out_bytes", "in_packets", "out_packets"):
                s[key.replace("bytes", "bps").replace("packets", "pps")] = \
                    self._rate(s[key], p.get(key), dt) if prev else None
            s["accounting_active"] = s["in_bytes"] is not None
            if s["accounting_active"]:
                acct += 1
                tot_in += s["in_bps"] or 0
                tot_out += s["out_bps"] or 0
            self._prev[s["unit"]] = (now, {k: s[k] for k in ("in_bytes", "out_bytes", "in_packets", "out_packets")})
            if s["in_bps"] is not None or s["out_bps"] is not None:
                h = self.history.setdefault(s["unit"], deque(maxlen=60))
                h.append(round((s["in_bps"] or 0) + (s["out_bps"] or 0), 1))
            s["history"] = list(self.history.get(s["unit"], ()))

        socks, complete = procnet.collect_sockets(self.proc)
        for so in socks:
            key = (so["kind"], so["inode"])
            prev = self._prev_sock.get(key)
            so["drop_rate"] = (self._rate(so["drops"], prev[1], now - prev[0])
                               if prev and so["drops"] is not None else None)
            self._prev_sock[key] = (now, so["drops"])

        active = sum(1 for s in services if s["active_state"] == "active")
        return {
            "ts": time.time(),
            "systemd_available": self.have_systemd and err is None,
            "systemd_error": err,
            "services": services,
            "sockets": socks,
            "sockets_pid_mapping_complete": complete,
            "totals": {"in_bps": tot_in, "out_bps": tot_out, "units": len(services),
                       "active_units": active, "accounting_units": acct,
                       "sockets": len(socks)},
        }
