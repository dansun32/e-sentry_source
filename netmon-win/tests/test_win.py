"""Offline tests for netmon_win.py (no Windows needed): parsers, rates, API shape, degradation, HTTP."""
import http.client
import json
import os
import re
import subprocess
import sys
import threading
import time

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
import netmon_win as nw  # noqa: E402

FIX = os.path.join(HERE, "fixtures")


def fx(name):
    with open(os.path.join(FIX, name), encoding="utf-8") as fh:
        return fh.read()


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def fixture_runner(calls=None):
    def run(cmd, timeout=0):
        if calls is not None:
            calls.append(cmd[0])
        if cmd[0] == "sc":
            return 0, fx("sc_queryex.txt"), ""
        if cmd[0] == "tasklist":
            return 0, fx("tasklist_svc.csv"), ""
        if cmd[0] == "netstat":
            return 0, fx("netstat_ano.txt"), ""
        return 1, "", "unexpected"
    return run


def etw_snap(groups, active=True, services=None):
    return {"schema": "netmon-etw/1", "etw": {"active": active, "error": None if active else "not elevated"},
            "services": services or [{"name": n, "displayName": n.upper(), "state": "running", "startType": "auto",
                                      "pid": g["pid"], "group": g["id"]} for g in groups for n in g["services"]],
            "groups": groups, "nonService": {"inBytes": 10, "outBytes": 5}}


def grp(pid, names, i, o):
    return {"id": "pid:%d" % pid, "pid": pid, "process": "svchost.exe", "services": names,
            "attribution": "exclusive" if len(names) == 1 else "shared-process", "inBytes": i, "outBytes": o}


class StubEtw(nw.EtwFeed):
    def __init__(self, snap=None, error=None):
        super().__init__(["x"] if snap else None)
        self.snap = snap
        if error:
            self.error = error

    def snapshot(self):
        return self.snap


# ------------------------------------------------------------------ parsers
def test_parse_sc_queryex():
    s = nw.parse_sc_queryex(fx("sc_queryex.txt"))
    assert [x["name"] for x in s] == ["Dnscache", "NlaSvc", "netprofm", "PrivateInternetAccessService", "Spooler"]
    assert {k: s[0][k] for k in ("name", "displayName", "state", "pid")} == \
        {"name": "Dnscache", "displayName": "DNS Client", "state": "running", "pid": 1880}
    assert s[1]["shared"] is True and s[4]["state"] == "stopped" and s[4]["pid"] == 0


def test_parse_tasklist_and_netstat():
    t = nw.parse_tasklist_svc(fx("tasklist_svc.csv"))
    assert t[2240] == {"image": "svchost.exe", "services": ["NlaSvc", "netprofm"]}
    assert t[7312]["services"] == [] and t[0]["services"] == []
    n = nw.parse_netstat_ano(fx("netstat_ano.txt"))
    assert n[4120] == {"tcp": 2, "udp": 0, "listen": 0}
    assert n[2240] == {"tcp": 1, "udp": 1, "listen": 1}  # localised state word still counted as listening
    assert n[1032]["listen"] == 2


def test_windows_label():
    assert nw.windows_label({"ProductName": "Windows 10 Pro", "DisplayVersion": "24H2", "CurrentBuild": "26100", "UBR": 2314}) \
        == "Windows 11 Pro 24H2 / build 26100.2314"
    assert nw.windows_label({"ProductName": "Windows 10 Home", "ReleaseId": "2009", "CurrentBuild": "19045", "UBR": 5011}) \
        == "Windows 10 Home 2009 / build 19045.5011"


def test_groups_from_fallback():
    g, rows = nw.groups_from_fallback(nw.parse_sc_queryex(fx("sc_queryex.txt")), nw.parse_tasklist_svc(fx("tasklist_svc.csv")))
    by = {x["pid"]: x for x in g}
    assert by[2240]["services"] == ["netprofm", "NlaSvc"] and by[2240]["attribution"] == "shared-process"
    assert by[3000]["services"] == ["WinHttpAutoProxySvc"]  # only known from tasklist
    assert all(x["inBytes"] is None for x in g)
    assert next(r for r in rows if r["name"] == "Spooler")["group"] is None


def test_capture_rows():
    rows, c = nw.capture_rows(json.loads(fx("raw_admin.json")))
    kinds = [r["kind"] for r in rows]
    assert kinds[0] == "driver" and rows[0]["count"] == "2 adapters" and rows[0]["detail"] == "running"
    cap = {r["pid"]: r for r in rows if r["kind"] == "capture"}
    assert set(cap) == {7312, 6600, 8800}
    assert cap[7312]["detail"] == "module+handle" and "Npcap" in cap[7312]["proto"]
    assert cap[8800]["proto"] == "\\Device\\NPCAP_LOOPBACK"
    assert cap[6600]["procName"] == "<b>evil</b>.exe"  # raw; the page escapes it
    assert kinds.count("wfp") == 3 and kinds.count("callout") == 2
    assert c == {"capture": 3, "raw": 0, "wfpFilters": 412, "wfpCallouts": 57}
    assert nw.capture_rows(None) == ([], {"capture": None, "raw": None, "wfpFilters": None, "wfpCallouts": None})


# ------------------------------------------------------------------ sampler / rates
def make_sampler(etw, raw=None, admin=True, calls=None):
    clk = Clock()
    raw = raw or nw.RawFeed(None)
    s = nw.Sampler(etw, raw, nw.FallbackFeed(runner=fixture_runner(calls), clock=clk), clock=clk,
                   os_label="Windows 11 Pro 24H2 / build 26100.2314", admin=admin, min_interval=0)
    return s, clk


def test_rates_separate_in_out_and_shared_group():
    etw = StubEtw(etw_snap([grp(2240, ["NlaSvc", "netprofm"], 1000, 500), grp(4120, ["PIA"], 0, 0)]))
    s, clk = make_sampler(etw)
    d1 = s.sample()
    assert d1["mode"] == "etw" and d1["banner"] == ["netmon-raw.exe not found"]
    assert all(x["ingressRate"] is None for x in d1["services"])  # first sample: no delta yet
    clk.t += 2
    etw.snap = etw_snap([grp(2240, ["NlaSvc", "netprofm"], 3048, 600), grp(4120, ["PIA"], 0, 4096)])
    d = s.sample()
    by = {x["id"]: x for x in d["services"]}
    shared = by["pid:2240"]
    assert shared["name"] == "NlaSvc +1" and shared["members"] == ["NlaSvc", "netprofm"]
    assert shared["ingressRate"] == 1024 and shared["egressRate"] == 50
    assert "not split" in shared["description"]
    assert by["pid:4120"]["ingressRate"] == 0 and by["pid:4120"]["egressRate"] == 2048
    assert d["totals"]["ingressRate"] == 1024 and d["totals"]["egressRate"] == 2098
    assert d["totals"]["monitored"] == 3 and d["totals"]["running"] == 3
    assert shared["history"] == [pytest.approx((1024 + 50) / 1024)]
    assert d["totals"]["nonServiceIn"] == 10
    # counter went backwards (helper restarted): n/a instead of a negative or huge rate
    clk.t += 1
    etw.snap = etw_snap([grp(2240, ["NlaSvc", "netprofm"], 5, 5), grp(4120, ["PIA"], 0, 5000)])
    by = {x["id"]: x for x in s.sample()["services"]}
    assert by["pid:2240"]["ingressRate"] is None and by["pid:4120"]["egressRate"] == 904


def test_api_shape_matches_live_page_contract():
    s, clk = make_sampler(StubEtw(etw_snap([grp(1880, ["Dnscache"], 1, 1)])),
                          raw=nw.RawFeed(["raw"], runner=lambda c, t=0: (0, fx("raw_admin.json"), "")))
    s.raw.poll_once()
    d = s.sample()
    for k in ("version", "ts", "os", "host", "services", "sockets", "totals", "banner", "mode", "helpers", "is_admin"):
        assert k in d, k
    for k in ("ingressRate", "egressRate", "running", "monitored", "sockets", "capture", "raw", "wfpFilters"):
        assert k in d["totals"], k
    svc = d["services"][0]
    for k in ("name", "id", "monitored", "activeState", "ingress", "egress", "ingressRate", "egressRate", "history",
              "description", "members", "pid", "connections"):
        assert k in svc, k
    for r in d["sockets"]:
        assert set(r) >= {"kind", "procName", "pid", "proto", "detail", "count"}
    json.dumps(d)


def test_degraded_no_etw_helper_uses_sc_tasklist_netstat():
    calls = []
    s, clk = make_sampler(StubEtw(None, error="netmon-etw.exe not found"), admin=False, calls=calls)
    d = s.sample()
    assert d["mode"] == "fallback"
    assert any("FALLBACK MODE" in b and "not found" in b for b in d["banner"])
    assert any("Administrator" in b for b in d["banner"])
    assert any("netmon-raw.exe not found" in b for b in d["banner"])
    assert set(calls) == {"sc", "tasklist", "netstat"}
    by = {x["pid"]: x for x in d["services"]}
    assert by[4120]["monitored"] is False and by[4120]["ingressRate"] is None
    assert by[4120]["connections"] == {"tcp": 2, "udp": 0, "listen": 0}
    assert by[3000]["connections"] == {"tcp": 0, "udp": 0, "listen": 0}
    assert d["totals"]["running"] == 4 and d["totals"]["monitored"] == 0
    assert d["totals"]["capture"] is None and d["sockets"] == []
    clk.t += 1  # cached within the fallback period: no new commands
    s.sample()
    assert len(calls) == 3


def test_degraded_etw_helper_without_admin():
    s, _ = make_sampler(StubEtw(etw_snap([grp(1880, ["Dnscache"], None, None)], active=False)), admin=False)
    d = s.sample()
    assert d["mode"] == "etw-services"
    assert any("ETW byte counters off: not elevated" in b for b in d["banner"])
    assert d["services"][0]["monitored"] is False and d["services"][0]["connections"]["udp"] == 2


def test_raw_feed_errors_are_reported():
    r = nw.RawFeed(["raw"], runner=lambda c, t=0: (5, "", "FwpmEngineOpen0: error 5: Access is denied"))
    r.poll_once()
    assert r.status == "error" and "Access is denied" in r.error
    r = nw.RawFeed(["raw"], runner=lambda c, t=0: (0, '{"schema":"other"}', ""))
    r.poll_once()
    assert r.status == "error"


# ------------------------------------------------------------------ real subprocess with a fake helper
def test_etw_feed_subprocess_and_clean_stop():
    feed = nw.EtwFeed([sys.executable, os.path.join(HERE, "fake_etw.py")], interval_ms=250)
    feed.start()
    deadline = time.time() + 10
    while feed.snapshot() is None and time.time() < deadline:
        time.sleep(0.05)
    snap = feed.snapshot()
    assert snap and snap["schema"] == "netmon-etw/1" and feed.status == "running"
    proc = feed.proc
    feed.stop()  # closes stdin -> fake exits by itself (no kill)
    assert proc.poll() is not None and proc.returncode == 0


def test_etw_feed_reports_crash():
    feed = nw.EtwFeed([sys.executable, os.path.join(HERE, "fake_etw.py"), "--crash"], interval_ms=250)
    feed.start()
    deadline = time.time() + 10
    while feed.status != "exited" and time.time() < deadline:
        time.sleep(0.05)
    feed.stop()
    assert feed.status == "exited" and "code 7" in feed.error and "fake crash" in feed.error


def test_etw_feed_missing():
    f = nw.EtwFeed(None)
    assert f.status == "missing" and f.snapshot() is None and "not found" in f.error


# ------------------------------------------------------------------ HTTP + page
@pytest.fixture()
def server():
    s, _ = make_sampler(StubEtw(etw_snap([grp(1880, ["Dnscache"], 1, 1)])))
    srv = nw.make_server(s, 0)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    yield srv.server_address[1]
    srv.shutdown()
    srv.server_close()


def req(port, method="GET", path="/", host=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.request(method, path, headers={"Host": host or "127.0.0.1:%d" % port})
    r = c.getresponse()
    body = r.read()
    return r.status, dict(r.getheaders()), body


def test_http_rules(server):
    st, h, body = req(server)
    assert st == 200 and b"WINDOWS SERVICES (SORTED TOP-DOWN BY THROUGHPUT)" in body
    assert not any(k.lower().startswith("access-control") for k in h)
    st, h, body = req(server, path="/api/data", host="localhost:%d" % server)
    assert st == 200 and json.loads(body)["services"][0]["name"] == "Dnscache"
    assert req(server, host="evil.example:%d" % server)[0] == 421
    assert req(server, "POST", "/api/data")[0] == 405
    assert req(server, path="/../netmon_win.py")[0] == 404


def test_bind_loopback_only():
    s, _ = make_sampler(StubEtw(None))
    srv = nw.make_server(s, 0)
    try:
        assert srv.server_address[0] == "127.0.0.1"
    finally:
        srv.server_close()


def test_page_keeps_identity_and_is_windows():
    page = open(os.path.join(ROOT, "netmon.html"), encoding="utf-8").read()
    orig = open(os.path.join(ROOT, "page", "base-live.html"), encoding="utf-8").read()
    cdn = re.compile(r'(?:src|url)\(?["\']?(https://[^"\')]+)')
    assert cdn.findall(page) == cdn.findall(orig)  # same Tailwind / Lucide / Google Fonts links
    style = re.compile(r"<style>.*?</style>", re.S)
    assert style.search(page).group(0) == style.search(orig).group(0)  # identical CSS
    for needle in ("WINDOWS SERVICES (SORTED TOP-DOWN BY THROUGHPUT)", "ETW kernel TCP/IP", "CAPTURE / RAW / WFP PANEL",
                   "Microsoft-Windows-Kernel-Network", 'id="dbus-drawer"', 'id="services-list"', 'id="raw-sockets-list"'):
        assert needle in page, needle
    for gone in ("systemd1", "IPAccounting", "/proc/net", "hosts.deny"):
        assert gone not in page, gone
    # every ${...} interpolation of row data in innerHTML templates goes through esc() or is numeric/formatted
    for m in re.finditer(r"\$\{(sock|service)\.(\w+)", page):
        assert m.group(2) in ("conns", "monitored"), m.group(0)  # numbers / boolean tests only


MOD = nw


@pytest.fixture()
def cors_port():
    s, _ = make_sampler(StubEtw(etw_snap([grp(1880, ["Dnscache"], 1, 1)])))
    srv = nw.make_server(s, 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()
    srv.server_close()


@pytest.fixture()
def cors_extra_port():
    s, _ = make_sampler(StubEtw(etw_snap([grp(1880, ["Dnscache"], 1, 1)])))
    srv = nw.make_server(s, 0, ["https://mirror.example"])
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()
    srv.server_close()


# ------------------------------------------------------------------ CORS for the hosted page
def _req(port, method, path, headers):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    h = {"Host": "127.0.0.1:%d" % port}
    h.update(headers)
    c.request(method, path, headers=h)
    r = c.getresponse()
    body = r.read()
    return r.status, {k.lower(): v for k, v in r.getheaders()}, body


@pytest.mark.parametrize("origin", ["https://dansun32.github.io", "https://e-sentry.net", "https://www.e-sentry.net"])
def test_cors_allowed_origin_gets_data(cors_port, origin):
    st, h, body = _req(cors_port, "GET", "/api/data", {"Origin": origin})
    assert st == 200 and "services" in json.loads(body)
    assert h["access-control-allow-origin"] == origin and h["vary"] == "Origin"
    assert "access-control-allow-credentials" not in h


@pytest.mark.parametrize("origin", ["https://evil.example", "null", "https://dansun32.github.io.evil.example",
                                    "http://dansun32.github.io", "https://e-sentry.net.evil.example"])
def test_cors_denied_origin_gets_nothing(cors_port, origin):
    st, h, body = _req(cors_port, "GET", "/api/data", {"Origin": origin})
    assert not [k for k in h if k.startswith("access-control")]  # browser refuses to hand the reply to the page
    st, h, _ = _req(cors_port, "OPTIONS", "/api/data", {"Origin": origin, "Access-Control-Request-Method": "GET",
                                                       "Access-Control-Request-Private-Network": "true"})
    assert st == 403 and not [k for k in h if k.startswith("access-control")]


def test_cors_only_on_api_data(cors_port):
    st, h, _ = _req(cors_port, "GET", "/", {"Origin": "https://e-sentry.net"})
    assert st == 200 and "access-control-allow-origin" not in h  # the page itself is never shared
    st, h, _ = _req(cors_port, "GET", "/api/data", {})
    assert st == 200 and "access-control-allow-origin" not in h  # no Origin: no CORS header
    st, h, _ = _req(cors_port, "GET", "/api/data", {"Origin": "http://127.0.0.1:%d" % cors_port})
    assert st == 200 and "access-control-allow-origin" not in h  # same-origin page


def test_cors_preflight(cors_port):
    o = "https://dansun32.github.io"
    st, h, _ = _req(cors_port, "OPTIONS", "/api/data", {"Origin": o, "Access-Control-Request-Method": "GET",
                                                       "Access-Control-Request-Private-Network": "true"})
    assert st == 204 and h["access-control-allow-origin"] == o and h["access-control-allow-methods"] == "GET"
    assert h["access-control-allow-private-network"] == "true" and h["vary"] == "Origin"
    st, h, _ = _req(cors_port, "OPTIONS", "/api/data", {"Origin": o, "Access-Control-Request-Method": "GET"})
    assert st == 204 and "access-control-allow-private-network" not in h
    st, h, _ = _req(cors_port, "OPTIONS", "/api/data", {"Origin": o, "Access-Control-Request-Method": "GET",
                                                       "Access-Control-Request-Headers": "cache-control"})
    assert st == 204 and h["access-control-allow-headers"] == "cache-control"
    # writes, odd headers and other paths are never allowed cross-origin
    for extra in ({"Access-Control-Request-Method": "POST"}, {"Access-Control-Request-Method": "DELETE"},
                  {"Access-Control-Request-Method": "GET", "Access-Control-Request-Headers": "x-evil"}):
        st, h, _ = _req(cors_port, "OPTIONS", "/api/data", dict({"Origin": o}, **extra))
        assert st == 403 and "access-control-allow-origin" not in h
    st, h, _ = _req(cors_port, "OPTIONS", "/", {"Origin": o, "Access-Control-Request-Method": "GET"})
    assert st == 405 and "access-control-allow-origin" not in h
    st, h, _ = _req(cors_port, "POST", "/api/data", {"Origin": o})
    assert st == 405 and "access-control-allow-origin" not in h
    st, h, _ = _req(cors_port, "OPTIONS", "/api/data", {"Origin": o, "Access-Control-Request-Method": "GET",
                                                       "Host": "evil.example:%d" % cors_port})
    assert st == 421 and "access-control-allow-origin" not in h


def test_allow_origin_flag(cors_extra_port):
    st, h, _ = _req(cors_extra_port, "GET", "/api/data", {"Origin": "https://mirror.example"})
    assert st == 200 and h["access-control-allow-origin"] == "https://mirror.example"


@pytest.mark.parametrize("bad", ["*", "null", "https://x.example/path", "ftp://x.example", "https://*.example"])
def test_allow_origin_rejects_bad_values(bad):
    with pytest.raises(Exception):
        MOD.check_origin(bad)
    assert MOD.check_origin("https://Mirror.example:8443/") == "https://mirror.example:8443"


# ------------------------------------------------------------------ --log-file / --pidfile (hidden start)
import signal, socket, subprocess, time as _time

SCRIPT = os.path.join(ROOT, "netmon_win.py")


def test_log_file_and_pidfile(tmp_path):
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    lf, pf = str(tmp_path / "e-sentry" / "helper.log"), str(tmp_path / "e-sentry" / "helper.pid")
    p = subprocess.Popen([sys.executable, SCRIPT, "--fallback", "--port", str(port), "--log-file", lf, "--pidfile", pf],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        for _ in range(50):
            try:
                st = req(port, path="/api/data")[0]
                break
            except OSError:
                _time.sleep(0.1)
        assert st == 200
        assert open(pf).read().strip() == str(p.pid)
    finally:
        p.send_signal(signal.SIGINT)
        out, err = p.communicate(timeout=10)
    assert out == b"" and err == b""  # everything went to the log
    log = open(lf).read()
    assert "netmon-win starting, PID %d" % p.pid in log and "netmon-win (read-only) on" in log
    assert not os.path.exists(pf)  # removed on exit


def test_bind_failure_is_logged(tmp_path):
    blocker = socket.socket(); blocker.bind(("127.0.0.1", 0)); blocker.listen(1)
    port = blocker.getsockname()[1]
    lf, pf = str(tmp_path / "helper.log"), str(tmp_path / "helper.pid")
    try:
        r = subprocess.run([sys.executable, SCRIPT, "--fallback", "--port", str(port), "--log-file", lf, "--pidfile", pf],
                           capture_output=True, timeout=20)
    finally:
        blocker.close()
    assert r.returncode == 1 and "ERROR: cannot listen on 127.0.0.1:%d" % port in open(lf).read()
    assert not os.path.exists(pf)
