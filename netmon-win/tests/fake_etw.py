"""Fake netmon-etw.exe: prints netmon-etw/1 JSON lines with growing counters; stops on stdin EOF.
usage: python fake_etw.py [--interval-ms N] [--exit-on-stdin-eof] [--no-admin] [--crash]"""
import json, math, sys, threading, time

args = sys.argv[1:]
interval = int(args[args.index("--interval-ms") + 1]) / 1000.0 if "--interval-ms" in args else 0.2
interval = min(interval, 0.3)
if "--crash" in args:
    print("netmon-etw: fake crash for tests", file=sys.stderr, flush=True)
    sys.exit(7)
admin = "--no-admin" not in args
stop = threading.Event()
if "--exit-on-stdin-eof" in args:
    def watch():
        while sys.stdin.buffer.read(256):
            pass
        stop.set()
    threading.Thread(target=watch, daemon=True).start()

SVCS = [("Dnscache", "DNS Client", 1880), ("NlaSvc", "Network Location Awareness", 2240),
        ("netprofm", "Network List Service", 2240), ("PrivateInternetAccessService", "Private Internet Access Service", 4120),
        ("wuauserv", "Windows Update", 3300), ("<img src=x onerror=alert(1)>", "XSS probe", 5100),
        ("Spooler", "Print Spooler", 0)]
PROC = {1880: "svchost.exe", 2240: "svchost.exe", 4120: "pia-service.exe", 3300: "svchost.exe", 5100: "evil.exe"}
RATE = {1880: (2500, 900), 2240: (400, 300), 4120: (150000, 42000), 3300: (64000, 2000), 5100: (0, 0)}
t0 = time.time()
seq = 0
while not stop.is_set():
    stop.wait(interval)
    seq += 1
    t = time.time() - t0
    groups = {}
    for name, disp, pid in SVCS:
        if pid:
            groups.setdefault(pid, []).append(name)
    gl = []
    for pid, names in sorted(groups.items()):
        ri, ro = RATE[pid]
        wob = lambda r: int(r * t + 0.6 * r * math.sin(t * 1.3 + pid)) if r else 0
        gl.append({"id": "pid:%d" % pid, "pid": pid, "process": PROC[pid], "services": sorted(names, key=str.lower),
                   "attribution": "exclusive" if len(names) == 1 else "shared-process",
                   "inBytes": max(0, wob(ri)) if admin else None, "outBytes": max(0, wob(ro)) if admin else None})
    snap = {"schema": "netmon-etw/1", "type": "snapshot", "version": "fake", "seq": seq, "ts": time.time(), "admin": admin,
            "etw": {"active": admin, "session": "netmon-etw", "error": None if admin else "not elevated: run as Administrator for ETW kernel TCP/IP bytes",
                    "events": seq * 100, "eventsLost": 0},
            "scmError": None,
            "services": [{"name": n, "displayName": d, "state": "running" if p else "stopped", "startType": "auto",
                          "pid": p, "group": ("pid:%d" % p) if p else None} for n, d, p in SVCS],
            "groups": gl, "nonService": {"pid": -1, "process": "(non-service processes)", "inBytes": int(9000 * t), "outBytes": int(3000 * t)},
            "topNonService": []}
    try:
        sys.stdout.write(json.dumps(snap) + "\n")
        sys.stdout.flush()
    except BrokenPipeError:
        break
