import http.client
import json
import threading
import pytest
from netmonlib.actions import AuditLog, Executor, Policy
from netmonlib.server import App, make_server
from test_actions import Recorder


class FakeSampler:
    have_systemd = True

    def sample(self):
        return {"services": [], "sockets": [], "totals": {}, "systemd_available": True}

    def invalidate(self):
        pass


@pytest.fixture
def srv(tmp_path):
    rec = Recorder()
    ex = Executor(Policy(ssh_check=lambda: False), AuditLog(str(tmp_path / "a.log")), runner=rec, dry_run=True)
    app = App(FakeSampler(), ex, 0, launch_key="KEY123")
    s = make_server(app, "127.0.0.1", 0)
    t = threading.Thread(target=s.serve_forever, daemon=True)
    t.start()
    yield s, app, rec
    s.shutdown()
    s.server_close()


def req(s, method, path, body=None, headers=None, host=None):
    port = s.server_address[1]
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    h = {"Host": host or "127.0.0.1:%d" % port}
    h.update(headers or {})
    data = None
    if body is not None:
        data = json.dumps(body).encode() if not isinstance(body, bytes) else body
        h.setdefault("Content-Type", "application/json")
    c.request(method, path, body=data, headers=h)
    r = c.getresponse()
    out = r.read()
    return r, out


def login(s):
    r, _ = req(s, "GET", "/?k=KEY123")
    assert r.status == 303 and r.getheader("Location") == "/"
    ck = r.getheader("Set-Cookie")
    assert "HttpOnly" in ck and "SameSite=Strict" in ck
    cookie = ck.split(";")[0]
    r, page = req(s, "GET", "/", headers={"Cookie": cookie})
    assert r.status == 200
    assert r.getheader("X-Frame-Options") == "DENY" and "frame-ancestors 'none'" in r.getheader("Content-Security-Policy")
    page = page.decode()
    token = page.split('name="csrf-token" content="')[1].split('"')[0]
    assert len(token) > 20 and "{{" not in page
    return cookie, token


def test_bind_loopback_only():
    with pytest.raises(ValueError):
        make_server(App(FakeSampler(), None, 0), "0.0.0.0", 0)


def test_session_flow(srv):
    s, app, rec = srv
    r, _ = req(s, "GET", "/")
    assert r.status == 401
    r, _ = req(s, "GET", "/api/snapshot")
    assert r.status == 401
    r, _ = req(s, "GET", "/?k=wrong")
    assert r.status == 403
    cookie, token = login(s)
    r, body = req(s, "GET", "/api/snapshot", headers={"Cookie": cookie})
    assert r.status == 200 and "services" in json.loads(body)
    r, body = req(s, "GET", "/api/config", headers={"Cookie": cookie})
    assert json.loads(body)["dry_run"] is True
    r, _ = req(s, "GET", "/static/app.js")
    assert r.status == 200
    for bad in ["/static/../netmon.py", "/static/.hidden.js", "/static/index.html"]:
        r, _ = req(s, "GET", bad)
        assert r.status == 404, bad


def test_host_header_rebinding(srv):
    s, app, rec = srv
    r, _ = req(s, "GET", "/?k=KEY123", host="evil.example:%d" % s.server_address[1])
    assert r.status == 421
    r, _ = req(s, "GET", "/?k=KEY123", host="localhost:%d" % s.server_address[1])
    assert r.status == 303


def test_csrf_origin_and_actions(srv):
    s, app, rec = srv
    cookie, token = login(s)
    port = s.server_address[1]
    body = {"unit": "cups.service", "action": "stop"}
    # no token
    r, _ = req(s, "POST", "/api/unit/action", body, {"Cookie": cookie})
    assert r.status == 403
    # wrong token
    r, _ = req(s, "POST", "/api/unit/action", body, {"Cookie": cookie, "X-Netmon-Token": "nope"})
    assert r.status == 403
    # token without cookie
    r, _ = req(s, "POST", "/api/unit/action", body, {"X-Netmon-Token": token})
    assert r.status == 403
    # cross-origin
    r, _ = req(s, "POST", "/api/unit/action", body, {"Cookie": cookie, "X-Netmon-Token": token, "Origin": "http://evil.example"})
    assert r.status == 403
    # form content-type
    r, _ = req(s, "POST", "/api/unit/action", b"unit=cups.service", {"Cookie": cookie, "X-Netmon-Token": token,
                                                                     "Content-Type": "application/x-www-form-urlencoded"})
    assert r.status == 415
    H = {"Cookie": cookie, "X-Netmon-Token": token, "Origin": "http://127.0.0.1:%d" % port}
    r, out = req(s, "POST", "/api/unit/preview", {"unit": "cups.service", "action": "kill", "signal": "SIGKILL"}, H)
    assert r.status == 200 and json.loads(out)["cmd"][-3:] == ["--signal=SIGKILL", "--", "cups.service"]
    r, out = req(s, "POST", "/api/unit/action", body, H)
    d = json.loads(out)
    assert r.status == 200 and d["dry_run"] and rec.calls == []
    r, out = req(s, "POST", "/api/unit/action", {"unit": "dbus.service", "action": "stop"}, H)
    assert r.status == 403 and json.loads(out)["requires_force"]
    r, out = req(s, "POST", "/api/unit/action", {"unit": "dbus.service", "action": "stop", "force": True}, H)
    assert r.status == 200
    r, out = req(s, "POST", "/api/unit/action", {"unit": "bad;name", "action": "stop"}, H)
    assert r.status == 400
    r, out = req(s, "POST", "/api/pid/kill", {"pid": 1, "inode": 1, "signal": "SIGKILL"}, H)
    assert r.status == 403
    r, out = req(s, "POST", "/api/unit/action", b"[1,2]", H)
    assert r.status == 400
    r, out = req(s, "POST", "/api/unit/action", b"x" * 5000, H)
    assert r.status == 413
