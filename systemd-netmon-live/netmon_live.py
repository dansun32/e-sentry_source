#!/usr/bin/env python3
"""systemd-netmon live helper: serves the original mockup page with REAL data.

READ-ONLY: no actions, no POST. Binds 127.0.0.1 only. Python 3 stdlib only.

    python3 netmon_live.py          # works without root (other users' socket owners: unknown)
    sudo python3 netmon_live.py     # full inode -> PID mapping
    open https://e-sentry.net/      (the hosted dashboard reads http://127.0.0.1:8787/api/data)

    sudo python3 netmon_live.py --background   start, detach, return to the prompt (errors stay on screen)
    sudo python3 netmon_live.py --status       is it running?
    sudo python3 netmon_live.py --stop         stop the background helper

Data sources (parsing ported from systemd-netmon 2.0.0):
  * `systemctl list-units` + `systemctl show -p IPIngressBytes,IPEgressBytes,...` per service
    (counters exist only for units with IPAccounting=yes; others are reported as null)
  * /proc/net/raw, /proc/net/raw6, /proc/net/packet, inode -> PID via /proc/*/fd
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import re
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

VERSION = "1.4.0-live"
HERE = os.path.dirname(os.path.abspath(__file__))
PROC = "/proc"
UINT64_MAX = 2 ** 64 - 1
SHOW_PROPS = ["Id", "Description", "LoadState", "ActiveState", "SubState", "UnitFileState",
              "IPAccounting", "IPIngressBytes", "IPEgressBytes", "IPIngressPackets", "IPEgressPackets"]
IP_PROTOS = {0: "IP", 1: "ICMP", 2: "IGMP", 4: "IPIP", 6: "TCP", 17: "UDP", 41: "IPv6", 47: "GRE",
             50: "ESP", 51: "AH", 58: "ICMPv6", 89: "OSPF", 103: "PIM", 112: "VRRP", 132: "SCTP", 255: "RAW"}
ETH_P = {0x0000: "none", 0x0001: "ETH_P_802_3", 0x0003: "ETH_P_ALL", 0x0004: "ETH_P_802_2",
         0x0019: "ETH_P_80211_RAW", 0x0800: "ETH_P_IP", 0x0806: "ETH_P_ARP", 0x86DD: "ETH_P_IPV6",
         0x888E: "ETH_P_PAE", 0x88CC: "ETH_P_LLDP", 0x8100: "ETH_P_8021Q", 0x88F7: "ETH_P_1588"}
PACKET_TYPES = {1: "STREAM", 2: "DGRAM", 3: "RAW", 10: "PACKET"}


# ------------------------------------------------------------------ /proc/net parsing
def _ipv4(h):
    return socket.inet_ntop(socket.AF_INET, struct.pack("<I", int(h, 16)))


def _ipv6(h):
    return socket.inet_ntop(socket.AF_INET6, b"".join(struct.pack("<I", int(h[i:i + 8], 16)) for i in range(0, 32, 8)))


def parse_raw(text, family="raw"):
    out = []
    for line in text.splitlines()[1:]:
        f = line.split()
        if len(f) < 10:
            continue
        try:
            laddr, lport = f[1].split(":")
            proto = int(lport, 16)  # for raw sockets the "port" field is the IP protocol
            out.append({"kind": family, "inode": int(f[9]), "uid": int(f[7]),
                        "proto": "%s %s" % ("RAW6" if family == "raw6" else "RAW", IP_PROTOS.get(proto, "proto %d" % proto)),
                        "local": (_ipv6 if family == "raw6" else _ipv4)(laddr), "iface": None,
                        "drops": int(f[12]) if len(f) > 12 else None, "rmem": None})
        except (ValueError, IndexError, OSError):
            continue
    return out


def _ifname(idx):
    try:
        return socket.if_indextoname(idx)
    except OSError:
        return "if#%d" % idx


def parse_packet(text, ifname=_ifname):
    out = []
    for line in text.splitlines()[1:]:
        f = line.split()
        if len(f) < 9:
            continue
        try:
            stype, proto, ifidx = int(f[2]), int(f[3], 16), int(f[4])
            out.append({"kind": "packet", "inode": int(f[8]), "uid": int(f[7]),
                        "proto": "%s (%s)" % (ETH_P.get(proto, "0x%04x" % proto), PACKET_TYPES.get(stype, str(stype))),
                        "local": None, "iface": ifname(ifidx) if ifidx else "any", "drops": None, "rmem": int(f[6])})
        except (ValueError, IndexError):
            continue
    return out


def read_text(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def cgroup_unit(text):
    for line in text.splitlines():
        parts = line.split(":", 2)
        if len(parts) == 3 and (parts[0] == "0" or parts[1] == "name=systemd"):
            for seg in reversed([s for s in parts[2].split("/") if s]):
                if seg.endswith((".service", ".scope")):
                    return seg
    return None


def map_inodes(wanted, proc=PROC):
    """{inode: [pids]}, complete(bool: False if some /proc/PID/fd were unreadable)."""
    res, complete = {}, True
    try:
        pids = [d for d in os.listdir(proc) if d.isdigit()]
    except OSError:
        return res, False
    for d in pids:
        fd_dir = os.path.join(proc, d, "fd")
        try:
            fds = os.listdir(fd_dir)
        except PermissionError:
            complete = False
            continue
        except OSError:
            continue
        for fd in fds:
            try:
                link = os.readlink(os.path.join(fd_dir, fd))
            except OSError:
                continue
            if link.startswith("socket:["):
                try:
                    ino = int(link[8:-1])
                except ValueError:
                    continue
                if ino in wanted and int(d) not in res.setdefault(ino, []):
                    res[ino].append(int(d))
    return res, complete


def collect_sockets(proc=PROC):
    socks = (parse_raw(read_text(os.path.join(proc, "net/raw")), "raw")
             + parse_raw(read_text(os.path.join(proc, "net/raw6")), "raw6")
             + parse_packet(read_text(os.path.join(proc, "net/packet"))))
    imap, complete = map_inodes({s["inode"] for s in socks}, proc) if socks else ({}, True)
    for s in socks:
        pids = sorted(imap.get(s["inode"], []))
        s["pid"] = pids[0] if pids else None
        s["pids"] = pids
        s["procName"] = read_text(os.path.join(proc, str(pids[0]), "comm")).strip() or None if pids else None
        s["unit"] = cgroup_unit(read_text(os.path.join(proc, str(pids[0]), "cgroup"))) if pids else None
        s["packets"] = None  # the kernel keeps no per-socket packet counter for raw/packet sockets
    return socks, complete


# ------------------------------------------------------------------ systemd
def run(cmd, timeout=20.0):
    env = dict(os.environ, LC_ALL="C", SYSTEMD_PAGER="", SYSTEMD_COLORS="0")
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError as e:
        return 127, "", str(e)
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


def counter(v):
    v = (v or "").strip()
    if not v.isdigit():
        return None  # "[not set]" -> accounting off
    n = int(v)
    return None if n >= UINT64_MAX else n


def parse_show(text):
    blocks, cur = [], {}
    for line in text.splitlines():
        if not line.strip():
            if cur:
                blocks.append(cur)
                cur = {}
        elif "=" in line:
            k, v = line.split("=", 1)
            cur[k] = v
    if cur:
        blocks.append(cur)
    return blocks


def parse_list_units(text):
    out = []
    for line in text.splitlines():
        f = line.strip().lstrip("\u25cf*").split(None, 4)
        if len(f) >= 4:
            out.append({"unit": f[0], "load": f[1], "active": f[2], "sub": f[3]})
    return out


def os_label():
    name = ""
    for line in read_text("/etc/os-release").splitlines():
        if line.startswith("PRETTY_NAME="):
            name = line.split("=", 1)[1].strip().strip('"')
    return "%s / Linux %s" % (name or platform.system(), platform.release())


class Sampler:
    def __init__(self, runner=run, proc=PROC, have_systemd=None, clock=time.monotonic, min_interval=0.25):
        self.runner, self.proc, self.clock, self.min_interval = runner, proc, clock, min_interval
        self.have_systemd = os.path.isdir("/run/systemd/system") if have_systemd is None else have_systemd
        self.lock = threading.Lock()
        self.prev = {}
        self.units, self.units_ts = [], -1e9
        self.cache, self.cache_ts = None, -1e9
        self.history = {}

    def services(self, now):
        if not self.have_systemd:
            return [], "systemd is not running as init on this machine"
        if now - self.units_ts > 5 or not self.units:
            rc, out, err = self.runner(["systemctl", "list-units", "--type=service", "--state=running",
                                        "--plain", "--no-legend", "--no-pager"], 20)
            if rc != 0:
                return [], (err or out).strip() or "systemctl list-units failed (rc=%d)" % rc
            self.units, self.units_ts = [u["unit"] for u in parse_list_units(out)], now
        recs = []
        for i in range(0, len(self.units), 120):
            rc, out, _ = self.runner(["systemctl", "show", "--no-pager", "-p", ",".join(SHOW_PROPS), "--"]
                                     + self.units[i:i + 120], 20)
            for b in parse_show(out):
                if b.get("Id"):
                    recs.append({"name": b["Id"], "description": b.get("Description", ""),
                                 "activeState": b.get("ActiveState", ""), "subState": b.get("SubState", ""),
                                 "unitFileState": b.get("UnitFileState", ""),
                                 "ipAccounting": b.get("IPAccounting") == "yes",
                                 "ingress": counter(b.get("IPIngressBytes")), "egress": counter(b.get("IPEgressBytes")),
                                 "ingressPackets": counter(b.get("IPIngressPackets")),
                                 "egressPackets": counter(b.get("IPEgressPackets"))})
        return recs, None

    @staticmethod
    def rate(cur, prev, dt):
        if cur is None or prev is None or dt <= 0 or cur < prev:
            return None  # n/a, or counter reset because the unit restarted
        return (cur - prev) / dt

    def sample(self):
        with self.lock:
            now = self.clock()
            if self.cache is not None and now - self.cache_ts < self.min_interval:
                return self.cache
            svcs, err = self.services(now)
            tin = tout = 0.0
            for s in svcs:
                p = self.prev.get(s["name"])
                dt = now - p[0] if p else 0
                s["ingressRate"] = self.rate(s["ingress"], p[1] if p else None, dt)   # bytes/s
                s["egressRate"] = self.rate(s["egress"], p[2] if p else None, dt)
                s["monitored"] = s["ingress"] is not None
                self.prev[s["name"]] = (now, s["ingress"], s["egress"])
                tin += s["ingressRate"] or 0
                tout += s["egressRate"] or 0
                if s["ingressRate"] is not None or s["egressRate"] is not None:
                    h = self.history.setdefault(s["name"], deque(maxlen=60))
                    h.append(((s["ingressRate"] or 0) + (s["egressRate"] or 0)) / 1024.0)
                s["history"] = list(self.history.get(s["name"], ()))
            socks, complete = collect_sockets(self.proc)
            snap = {"version": VERSION, "ts": time.time(), "os": os_label(), "host": platform.node(),
                    "is_root": os.geteuid() == 0, "systemd_available": err is None, "systemd_error": err,
                    "services": svcs, "sockets": socks, "sockets_owner_complete": complete,
                    "totals": {"ingressRate": tin, "egressRate": tout, "running": len(svcs),
                               "monitored": sum(1 for s in svcs if s["monitored"]), "sockets": len(socks)}}
            self.cache, self.cache_ts = snap, now
            return snap


# Origins whose pages may read /api/data cross-origin (the hosted dashboard on GitHub Pages,
# shown through the e-sentry.net frame). Exact match only; add more with --allow-origin.
DEFAULT_ALLOWED_ORIGINS = ("https://dansun32.github.io", "https://e-sentry.net", "https://www.e-sentry.net")
_ORIGIN_RE = re.compile(r"^https?://[A-Za-z0-9.-]+(?::\d{1,5})?$")
_SAFE_REQ_HEADERS = {"accept", "accept-language", "content-language", "cache-control", "pragma"}


def check_origin(value: str) -> str:
    """argparse type for --allow-origin: scheme://host[:port], no path, no wildcard."""
    v = value.strip().rstrip("/")
    if not _ORIGIN_RE.match(v):
        raise argparse.ArgumentTypeError("origin must look like https://example.com[:port] (no path, no '*')")
    return v.lower()


# ------------------------------------------------------------------ HTTP
class Handler(BaseHTTPRequestHandler):
    sampler: Sampler = None  # type: ignore
    page_path = os.path.join(HERE, "netmon.html")
    server_version = "systemd-netmon-live"
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
                return self.send(500, b"netmon.html missing next to netmon_live.py", "text/plain")
        if path == "/api/data":
            extra = self.cors_headers(origin) if state == "allowed" else [("Vary", "Origin")]
            try:
                data = self.sampler.sample()
            except Exception as e:  # report instead of dropping the connection
                return self.send(500, json.dumps({"error": "%s: %s" % (type(e).__name__, e)}).encode(), "application/json")
            return self.send(200, json.dumps(data).encode(), "application/json", extra)
        return self.send(404, b'{"error":"not found"}', "application/json")

    do_HEAD = do_GET

    def do_POST(self):  # read-only helper
        self.send(405, b'{"error":"read-only"}', "application/json")

    do_PUT = do_DELETE = do_PATCH = do_POST  # never CORS


def make_server(sampler, port=8787, extra_origins=()):
    allowed = frozenset(DEFAULT_ALLOWED_ORIGINS) | frozenset(extra_origins)
    handler = type("H", (Handler,), {"sampler": sampler, "allowed_origins": allowed})
    srv = ThreadingHTTPServer(("127.0.0.1", port), handler)
    srv.daemon_threads = True
    return srv


# ------------------------------------------------------------------ background mode (--background / --stop / --status)
def default_paths(euid=None):
    """(pidfile, logfile). Root (sudo): /run + /var/log. Otherwise ~/.cache/e-sentry/."""
    if (os.geteuid() if euid is None else euid) == 0:
        return "/run/e-sentry-helper.pid", "/var/log/e-sentry-helper.log"
    d = os.path.join(os.path.expanduser("~"), ".cache", "e-sentry")
    return os.path.join(d, "helper.pid"), os.path.join(d, "helper.log")


def read_pidfile(path):
    try:
        with open(path) as fh:
            pid = int(fh.read().strip())
        return pid if pid > 1 else None
    except (OSError, ValueError):
        return None


def is_our_process(pid, proc=PROC):
    """True if /proc/PID is a python running netmon_live.py (guards against a stale pidfile / reused PID)."""
    try:
        with open(os.path.join(proc, str(pid), "cmdline"), "rb") as fh:
            args = fh.read().split(b"\0")
    except OSError:
        return False
    return any(os.path.basename(a.decode(errors="replace")) == "netmon_live.py" for a in args)


def running_pid(pidfile, proc=PROC):
    pid = read_pidfile(pidfile)
    return pid if pid and is_our_process(pid, proc) else None


def _open_private(path, flags, mode):
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, mode=0o755, exist_ok=True)
    return os.open(path, flags | getattr(os, "O_NOFOLLOW", 0), mode)  # never follow a planted symlink


def write_pidfile(path, pid):
    fd = _open_private(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    with os.fdopen(fd, "w") as fh:
        fh.write("%d\n" % pid)


def remove_pidfile(path, pid):
    if read_pidfile(path) == pid:
        try:
            os.unlink(path)
        except OSError:
            pass


def stop_helper(pidfile, proc=PROC, kill=os.kill, timeout=5.0, sleep=time.sleep):
    """SIGTERM the background helper. 0 = stopped, 1 = not running, 2 = not allowed / did not stop."""
    pid = running_pid(pidfile, proc)
    if pid is None:
        if read_pidfile(pidfile) is not None:
            try:
                os.unlink(pidfile)  # stale
            except OSError:
                pass
        print("e-sentry helper is not running (no live PID in %s)." % pidfile)
        return 1
    try:
        kill(pid, signal.SIGTERM)
    except PermissionError:
        print("ERROR: not allowed to stop PID %d; run it with sudo." % pid, file=sys.stderr)
        return 2
    except ProcessLookupError:
        return 1
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if not is_our_process(pid, proc):
            remove_pidfile(pidfile, pid)
            print("e-sentry helper stopped (PID %d)." % pid)
            return 0
        sleep(0.1)
    print("ERROR: PID %d did not stop within %.0fs." % (pid, timeout), file=sys.stderr)
    return 2


def daemonize(pidfile, logfile):
    """Detach (double fork + setsid). Returns None in the daemon. The original process gets back
    'OK <pid>' or 'ERROR <text>' once the daemon is set up (or '' if it died)."""
    sys.stdout.flush()
    sys.stderr.flush()
    r, w = os.pipe()
    pid = os.fork()
    if pid > 0:  # original process: wait for the daemon's verdict
        os.close(w)
        chunks = []
        while True:
            b = os.read(r, 4096)
            if not b:
                break
            chunks.append(b)
        os.close(r)
        os.waitpid(pid, 0)
        return b"".join(chunks).decode(errors="replace")
    os.close(r)
    try:
        os.setsid()
        if os.fork() > 0:
            os._exit(0)
        os.chdir("/")
        os.umask(0o022)
        log = _open_private(logfile, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
        write_pidfile(pidfile, os.getpid())
        null = os.open(os.devnull, os.O_RDONLY)
        os.dup2(null, 0)
        os.dup2(log, 1)
        os.dup2(log, 2)
        os.close(null)
        os.close(log)
        signal.signal(signal.SIGHUP, signal.SIG_IGN)
    except OSError as e:
        os.write(w, ("ERROR %s" % e).encode())
        os._exit(1)
    os.write(w, b"OK %d" % os.getpid())
    os.close(w)
    return None


def _sigterm(signum, frame):
    raise SystemExit(0)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=8787, help="port on 127.0.0.1 (default 8787)")
    ap.add_argument("--allow-origin", action="append", default=[], type=check_origin, metavar="ORIGIN",
                    help="extra site allowed to read /api/data (repeatable); built in: " + ", ".join(DEFAULT_ALLOWED_ORIGINS))
    ap.add_argument("--interval", type=float, default=0.25,
                    help="minimum seconds between real samples (hint; the page polls at its own 500/1000/2000ms setting)")
    ap.add_argument("-b", "--background", action="store_true",
                    help="check everything, then run detached and return to the prompt (log + pidfile, see --log-file)")
    ap.add_argument("--stop", action="store_true", help="stop the background helper")
    ap.add_argument("--status", action="store_true", help="say whether the background helper is running")
    ap.add_argument("--pidfile", help="default: /run/e-sentry-helper.pid as root, else ~/.cache/e-sentry/helper.pid")
    ap.add_argument("--log-file", help="background log; default: /var/log/e-sentry-helper.log as root, else ~/.cache/e-sentry/helper.log")
    a = ap.parse_args(argv)
    dpid, dlog = default_paths()
    pidfile, logfile = a.pidfile or dpid, a.log_file or dlog
    sudo = "sudo " if os.geteuid() == 0 else ""
    if a.stop:
        return stop_helper(pidfile)
    if a.status:
        pid = running_pid(pidfile)
        print("e-sentry helper running in background (PID %d), log %s" % (pid, logfile) if pid
              else "e-sentry helper is not running in background.")
        return 0 if pid else 3
    if a.background:
        pid = running_pid(pidfile)
        if pid:
            print("e-sentry helper already running in background (PID %d) - open https://e-sentry.net/ ; "
                  "stop with: %spython3 netmon_live.py --stop" % (pid, sudo))
            return 0
    sampler = Sampler(min_interval=a.interval)
    try:
        srv = make_server(sampler, a.port, a.allow_origin)
    except OSError as e:
        print("ERROR: cannot listen on 127.0.0.1:%d: %s" % (a.port, e.strerror or e), file=sys.stderr)
        if getattr(e, "errno", None) == 98:
            print("Is the helper already running? Check with: %spython3 netmon_live.py --status" % sudo, file=sys.stderr)
        return 1
    if not sampler.have_systemd:
        print("WARNING: systemd is not running as init here; the services list will be empty.", file=sys.stderr)
    if os.geteuid() != 0:
        print("NOTE: not root: owners of other users' raw/packet sockets show as 'unknown' (use sudo for all).",
              file=sys.stderr)
    if a.background:
        verdict = daemonize(pidfile, logfile)
        if verdict is not None:  # original process: report and return to the prompt
            srv.server_close()
            if verdict.startswith("OK "):
                print("e-sentry helper running in background (PID %s) - open https://e-sentry.net/ ; "
                      "stop with: %spython3 netmon_live.py --stop" % (verdict[3:], sudo))
                print("Log: %s" % logfile)
                return 0
            print("ERROR: background start failed: %s" % (verdict[6:] if verdict.startswith("ERROR ") else "helper exited"),
                  file=sys.stderr)
            return 1
        print("%s systemd-netmon live started in background, PID %d, port %d"
              % (time.strftime("%Y-%m-%d %H:%M:%S"), os.getpid(), srv.server_address[1]), flush=True)
    else:
        print("systemd-netmon live (read-only) on http://127.0.0.1:%d/  (Ctrl-C to stop)" % srv.server_address[1], flush=True)
        print("Live data for the hosted dashboard: open https://e-sentry.net/", flush=True)
    signal.signal(signal.SIGTERM, _sigterm)
    try:
        srv.serve_forever()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        srv.server_close()
        if a.background:
            remove_pidfile(pidfile, os.getpid())
            print("%s stopped" % time.strftime("%Y-%m-%d %H:%M:%S"), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
