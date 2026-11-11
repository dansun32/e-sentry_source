"""Serve the live page against a stub systemctl + fake /proc (for browser screenshots/tests).
usage: python3 tests/fakehost_server.py PORT"""
import math, os, pathlib, sys, tempfile, time
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE)); sys.path.insert(0, HERE)
import netmon_live as nl
from test_live import fake_proc

UNITS = [("nginx.service", 40000, 310000), ("ssh.service", 9000, 15000), ("systemd-resolved.service", 1500, 900),
         ("piavpn.service", 60000, 12000), ("cups.service", None, None), ("NetworkManager.service", None, None)]


def runner(cmd, timeout=0):
    t = time.time()
    if cmd[1] == "list-units":
        return 0, "".join("%s loaded active running x\n" % u[0] for u in UNITS), ""
    out = []
    for name, i, o in UNITS:
        # monotonic counters with a varying slope (rate r * (1 + 0.6 cos)) so the sparkline moves
        val = (lambda r: "[not set]") if i is None else (lambda r: str(int(5e6 + (t % 1e5) * r + 0.6 * r * math.sin(t + len(name)))))
        out.append("Id=%s\nDescription=d\nActiveState=active\nSubState=running\nUnitFileState=enabled\n"
                   "IPAccounting=%s\nIPIngressBytes=%s\nIPEgressBytes=%s\n" % (name, "no" if i is None else "yes", val(i), val(o)))
    return 0, "\n".join(out), ""


if __name__ == "__main__":
    s = nl.Sampler(runner=runner, proc=fake_proc(pathlib.Path(tempfile.mkdtemp())), have_systemd=True, min_interval=0.2)
    srv = nl.make_server(s, int(sys.argv[1]))
    print("up", flush=True)
    srv.serve_forever()
