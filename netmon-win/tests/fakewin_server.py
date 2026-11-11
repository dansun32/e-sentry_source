"""Serve the Windows page with fake helpers (for browser screenshots / manual checks), on Linux.
usage: python3 tests/fakewin_server.py PORT [--degraded]
  default:    fake_etw.py (admin, ETW active) + fake_raw.py (Npcap, WFP fixture)
  --degraded: no ETW helper, no raw helper, not admin -> sc/tasklist/netstat fixtures"""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE)); sys.path.insert(0, HERE)
import netmon_win as nw

FIX = os.path.join(HERE, "fixtures")


def fixture_runner():
    files = {"sc": "sc_queryex.txt", "tasklist": "tasklist_svc.csv", "netstat": "netstat_ano.txt"}

    def run(cmd, timeout=0):
        if cmd[0] in files:
            with open(os.path.join(FIX, files[cmd[0]]), encoding="utf-8") as fh:
                return 0, fh.read(), ""
        return 1, "", "unexpected"
    return run

if __name__ == "__main__":
    port, degraded = int(sys.argv[1]), "--degraded" in sys.argv
    if degraded:
        etw, raw = nw.EtwFeed(None), nw.RawFeed(None)
    else:
        etw = nw.EtwFeed([sys.executable, os.path.join(HERE, "fake_etw.py")], interval_ms=250)
        raw = nw.RawFeed([sys.executable, os.path.join(HERE, "fake_raw.py")], period=10)
    s = nw.Sampler(etw, raw, nw.FallbackFeed(runner=fixture_runner()), os_label="Windows 11 Pro 24H2 / build 26100.2314",
                   admin=not degraded, min_interval=0.2)
    etw.start(); raw.start()
    srv = nw.make_server(s, port)
    print("up", flush=True)
    try:
        srv.serve_forever()
    finally:
        etw.stop(); raw.stop()
