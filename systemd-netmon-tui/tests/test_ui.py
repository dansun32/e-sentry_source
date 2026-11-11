import os
import sys
import time
import pytest
import fakehost
from fakescreen import FakeScreen
from netmontui.actions import AuditLog, Executor, Policy
from netmontui.systemd import Sampler
from netmontui.ui import App

ENTER, ESC, TAB = 10, 27, 9


@pytest.fixture(scope="module")
def proc():
    return fakehost.setup()


def make_app(proc, tmp_path, rows=40, cols=140, **kw):
    s = Sampler(proc=proc, have_systemd=True, min_interval=0)
    log = str(tmp_path / "audit.log")
    ex = Executor(Policy(ssh_check=lambda: False), AuditLog(log), dry_run=kw.pop("dry_run", True), proc=proc,
                  read_only=kw.pop("read_only", False))
    app = App(s, ex)
    app.poller.snap = s.sample()
    time.sleep(0.2)
    app.poller.snap = s.sample()
    fs = FakeScreen(rows, cols)
    app.attach(fs, "mono", True)
    return app, fs, log


def frame(app, fs):
    app.draw()
    return fs.text()


def test_layout_and_sorting(proc, tmp_path):
    app, fs, _ = make_app(proc, tmp_path)
    t = frame(app, fs)
    lines = t.split("\n")
    assert "systemd-netmon-tui v3.0.0" in lines[0] and "[DRY-RUN]" in lines[0] and "Linux " in lines[0]
    assert "SYSTEMD TOTAL INGRESS" in lines[1] and "sockets active" in lines[2]
    assert "SYSTEMD NETWORK SERVICES" in lines[3] and "RAW / PACKET SOCKETS" in t
    order = [l.split()[2] for l in lines if l.startswith("│ ●")]
    assert order[:3] == ["piavpn.service", "systemd-resolved.service", "ssh.service"] or order[0] == "piavpn.service"
    assert "accounts-daemon.service" not in t  # failed unit hidden in "running" view
    assert "IPAccounting off" in t and "n/a" in t and "piavpn.service !" in t
    assert "Space" in lines[-1] and "Quit" in lines[-1]


def test_views_filter_pane(proc, tmp_path):
    app, fs, _ = make_app(proc, tmp_path)
    app.handle_key(ord("v"))
    assert "accounts-daemon.service" in frame(app, fs) and "avahi-daemon.service" in frame(app, fs)
    app.handle_key(ord("v"))
    t = frame(app, fs)
    assert "cups.service" not in t and "piavpn.service" in t
    app.handle_key(ord("v"))
    for ch in "/ssh":
        app.handle_key(ord(ch))
    app.handle_key(ENTER)
    t = frame(app, fs)
    assert "ssh.service" in t and "piavpn.service" not in t and "filter: ssh" in t
    app.handle_key(ord("/"))
    app.handle_key(ESC)
    assert app.filter == ""
    app.handle_key(TAB)
    assert app.focus == 1 and app.selected()["inode"] == 29041


def test_small_terminal_and_resize(proc, tmp_path):
    app, fs, _ = make_app(proc, tmp_path, rows=15, cols=60)
    assert "need at least 80x20" in frame(app, fs)
    fs.rows, fs.cols = 24, 80
    fs.erase()
    t = frame(app, fs)
    assert "SYSTEMD NETWORK SERVICES" in t and all(len(l) <= 80 for l in t.split("\n"))


def test_pause_reset_interval(proc, tmp_path):
    app, fs, _ = make_app(proc, tmp_path)
    app.handle_key(ord(" "))
    assert app.poller.paused and "PAUSED" in frame(app, fs)
    app.handle_key(ord(" "))
    assert not app.poller.paused
    app.handle_key(ord("r"))
    assert "piavpn.service" in app.baseline and app.sampler.history == {}
    app.handle_key(ord("3"))
    assert app.poller.interval == 2.0
    app.handle_key(ord("-"))
    assert app.poller.interval == 1.0


def test_menu_confirm_dry_run(proc, tmp_path):
    app, fs, log = make_app(proc, tmp_path)
    app.sel_key[0] = "cups.service"
    app.handle_key(ENTER)
    t = frame(app, fs)
    assert app.overlay == "menu" and "ACTIONS: cups.service" in t and "[m] Mask" in t and "[i] Enable IPAccounting" in t
    app.handle_key(ord("m"))
    t = frame(app, fs)
    assert app.overlay == "confirm" and "$ systemctl --no-ask-password mask -- cups.service" in t and "DRY-RUN" in t
    app.handle_key(ord(" "))  # toggle --now
    assert "mask --now -- cups.service" in frame(app, fs)
    app.handle_key(ord("y"))
    assert app.overlay is None and "DRY-RUN logged" in app.status[0]
    rec = open(log).read()
    assert '"mask"' in rec and '"--now"' in rec and '"dry-run"' in rec


def test_protected_requires_unit_name(proc, tmp_path):
    app, fs, log = make_app(proc, tmp_path)
    app.sel_key[0] = "piavpn.service"
    app.handle_key(ord("a"))
    app.handle_key(ord("k"))  # Kill SIGKILL
    t = frame(app, fs)
    assert "PROTECTED" in t and "Type piavpn.service" in t and "kill --signal=SIGKILL -- piavpn.service" in t
    app.handle_key(ord("y"))
    app.handle_key(ENTER)  # typed "y" != unit name
    assert app.overlay == "confirm" and "does not match" in app.status[0]
    for _ in range(3):
        app.handle_key(127)
    for ch in "piavpn.service":
        app.handle_key(ord(ch))
    app.handle_key(ENTER)
    assert app.overlay is None and "DRY-RUN logged" in app.status[0]
    assert '"forced": true' in open(log).read()


def test_socket_pid_kill_and_escape(proc, tmp_path):
    app, fs, log = make_app(proc, tmp_path)
    app.handle_key(TAB)
    app.move(to=2)  # tcpdump raw6 socket
    assert app.selected()["process"] == "tcpdump"
    app.handle_key(ENTER)
    app.handle_key(ord("t"))
    t = frame(app, fs)
    assert "$ kill -TERM 4102" in t and "PROTECTED" not in t
    app.handle_key(ESC)
    assert app.overlay is None and app.status[0] == "cancelled"
    app.handle_key(ENTER)
    app.handle_key(ord("t"))
    app.handle_key(ENTER)
    assert "DRY-RUN logged: kill -TERM 4102" in app.status[0]


def test_drawer_help_readonly(proc, tmp_path):
    app, fs, _ = make_app(proc, tmp_path, read_only=True)
    app.handle_key(ord("d"))
    t = frame(app, fs)
    assert "DETAILS / INFO" in t and "SELECTED UNIT" in t
    app.handle_key(ESC)
    app.handle_key(ord("?"))
    assert "KEYS" in frame(app, fs)
    app.handle_key(ESC)
    app.handle_key(ENTER)
    assert app.overlay is None and "read-only" in app.status[0] and "[READ-ONLY]" in frame(app, fs)
    assert app.handle_key(ord("q")) is False


def test_real_curses_under_pty(tmp_path):
    pytest.importorskip("pyte")
    from ptyscreen import PtyScreen
    here = os.path.dirname(__file__)
    s = PtyScreen([sys.executable, os.path.join(here, "fakehost.py")], cols=150, rows=40,
                  env={"FAKEHOST_AUDIT": str(tmp_path / "a.log")})
    try:
        s.pump(2.5)
        t = s.text()
        assert "systemd-netmon-tui v3.0.0" in t and "piavpn.service" in t and "ETH_P_ALL (RAW)" in t
        s.resize(100, 30)  # KEY_RESIZE path
        s.pump(1.0)
        t2 = s.text()
        assert "SYSTEMD NETWORK SERVICES" in t2 and len(t2.split("\n")[0]) == 100
        s.send("a", 0.5)
        s.send("t", 0.5)
        assert "kill --signal=SIGTERM" in s.text()
        s.send("\x1b", 0.8)
        s.send("q", 0.3)
    finally:
        st = s.close()
    assert st == 0
