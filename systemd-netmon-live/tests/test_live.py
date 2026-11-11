import http.client, json, os, sys, threading, time
import pytest
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import netmon_live as nl

FIX = os.path.join(HERE, "fixtures")
fx = lambda n: open(os.path.join(FIX, n)).read()


class FakeSystemctl:
    def __init__(self):
        self.ing = 8900400

    def __call__(self, cmd, timeout=0):
        if cmd[1] == "list-units":
            return 0, fx("systemctl_list_units.txt"), ""
        if cmd[1] == "show":
            return 0, fx("systemctl_show.txt").replace("IPIngressBytes=8900400", "IPIngressBytes=%d" % self.ing), ""
        return 1, "", "?"


def fake_proc(tmp_path):
    root = tmp_path / "proc"
    (root / "net").mkdir(parents=True)
    for n in ("raw", "raw6", "packet"):
        (root / "net" / n).write_text(fx("proc_net_%s.txt" % n))
    d = root / "482"
    (d / "fd").mkdir(parents=True)
    (d / "comm").write_text("<b>NetworkManager</b>\n")
    (d / "cgroup").write_text("0::/system.slice/NetworkManager.service\n")
    os.symlink("socket:[51209]", str(d / "fd" / "3"))
    return str(root)


@pytest.fixture
def sampler(tmp_path):
    clock = [100.0]
    fake = FakeSystemctl()
    s = nl.Sampler(runner=fake, proc=fake_proc(tmp_path), have_systemd=True, clock=lambda: clock[0], min_interval=0)
    return s, fake, clock


def test_shape_and_rates(sampler):
    s, fake, clock = sampler
    d1 = s.sample()
    assert set(d1) >= {"os", "services", "sockets", "totals", "systemd_available", "sockets_owner_complete"}
    assert set(d1["totals"]) == {"ingressRate", "egressRate", "running", "monitored", "sockets"}
    ssh = [x for x in d1["services"] if x["name"] == "ssh.service"][0]
    assert ssh["ingressRate"] is None and ssh["monitored"] and ssh["ingress"] == 8900400
    fake.ing += 4096
    clock[0] += 2
    d2 = s.sample()
    by = {x["name"]: x for x in d2["services"]}
    assert by["ssh.service"]["ingressRate"] == 2048.0 and by["ssh.service"]["egressRate"] == 0.0  # separate deltas
    assert by["cups.service"]["ingress"] is None and by["cups.service"]["ingressRate"] is None and not by["cups.service"]["monitored"]
    assert by["avahi-daemon.service"]["ingress"] is None  # UINT64_MAX = not set
    assert d2["totals"]["ingressRate"] == 2048.0 and d2["totals"]["monitored"] == 1 and d2["totals"]["running"] == 3
    socks = {x["inode"]: x for x in d2["sockets"]}
    assert socks[51209]["procName"] == "<b>NetworkManager</b>" and socks[51209]["pid"] == 482  # escaped client-side
    assert socks[51209]["unit"] == "NetworkManager.service" and socks[51209]["rmem"] == 0
    assert socks[18492]["drops"] == 17 and socks[18492]["pid"] is None
    assert all(x["packets"] is None for x in d2["sockets"])
    json.dumps(d2)


def test_no_systemd(tmp_path):
    s = nl.Sampler(runner=lambda *a: (1, "", ""), proc=fake_proc(tmp_path), have_systemd=False)
    d = s.sample()
    assert d["services"] == [] and not d["systemd_available"] and d["systemd_error"] and d["totals"]["sockets"] == 6


@pytest.fixture
def server(sampler):
    srv = nl.make_server(sampler[0], 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv
    srv.shutdown()
    srv.server_close()


def get(srv, path, host=None, method="GET"):
    port = srv.server_address[1]
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.request(method, path, headers={"Host": host or "127.0.0.1:%d" % port, "Origin": "http://evil.example"})
    r = c.getresponse()
    return r, r.read()


def test_http(server):
    port = server.server_address[1]
    r, body = get(server, "/")
    assert r.status == 200 and b"cdn.tailwindcss.com" in body and b"/api/data" in body
    r, body = get(server, "/api/data")
    assert r.status == 200 and "services" in json.loads(body)
    assert not [h for h in r.getheaders() if h[0].lower().startswith("access-control")]
    assert get(server, "/api/data", host="localhost:%d" % port)[0].status == 200
    assert get(server, "/api/data", host="evil.example:%d" % port)[0].status == 421
    assert get(server, "/api/data", host="127.0.0.1")[0].status == 421
    assert get(server, "/api/data", method="POST")[0].status == 405
    assert get(server, "/../netmon_live.py")[0].status == 404


def test_binds_loopback_only(sampler):
    srv = nl.make_server(sampler[0], 0)
    try:
        assert srv.server_address[0] == "127.0.0.1"
    finally:
        srv.server_close()
