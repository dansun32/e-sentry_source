import os
import pytest
from netmontui import maximise as m

ALL = {"gnome-terminal", "xfce4-terminal", "mate-terminal", "tilix", "konsole", "kitty", "xterm",
       "x-terminal-emulator", "wmctrl", "xdotool"}
which_all = lambda n: "/usr/bin/" + n if n in ALL else None
CMD = ["/usr/bin/python3", "/home/dan/systemd-netmon-tui/netmon_tui.py", "--no-spawn", "--hold"]


@pytest.mark.parametrize("term,expect", [
    ("gnome-terminal", ["gnome-terminal", "--maximize", "--"] + CMD),
    ("xfce4-terminal", ["xfce4-terminal", "--maximize", "-x"] + CMD),
    ("mate-terminal", ["mate-terminal", "--maximize", "-x"] + CMD),
    ("tilix", ["tilix", "--maximize", "-e", " ".join(CMD)]),
    ("konsole", ["konsole", "-e"] + CMD),
    ("kitty", ["kitty", "--start-as=maximized"] + CMD),
    ("xterm", ["xterm", "-maximized", "-e"] + CMD),
    ("x-terminal-emulator", ["x-terminal-emulator", "-e"] + CMD),
])
def test_terminal_argv(term, expect):
    name, argv, _ = m.choose_terminal(CMD, {"DISPLAY": ":0"}, which_all, preferred=term)
    assert name == term and argv == expect


def test_tilix_quotes_paths_with_spaces():
    _, argv, _ = m.choose_terminal(["/a b/python3", "x"], {}, which_all, preferred="tilix")
    assert argv[-1] == "'/a b/python3' x"


@pytest.mark.parametrize("desk,first", [("X-Cinnamon", "gnome-terminal"), ("XFCE", "xfce4-terminal"),
                                        ("MATE", "mate-terminal"), ("KDE", "konsole"), ("", "gnome-terminal")])
def test_desktop_preference(desk, first):
    assert m.terminal_order({"XDG_CURRENT_DESKTOP": desk})[0] == first


def test_order_respects_env_and_availability():
    assert m.terminal_order({"NETMON_TERMINAL": "xterm", "XDG_CURRENT_DESKTOP": "X-Cinnamon"})[:2] == ["xterm", "gnome-terminal"]
    only_xterm = lambda n: "/usr/bin/xterm" if n == "xterm" else None
    assert m.choose_terminal(CMD, {"XDG_CURRENT_DESKTOP": "X-Cinnamon"}, only_xterm)[0] == "xterm"
    assert m.choose_terminal(CMD, {}, lambda n: None) is None


def test_spawn_paths():
    calls = []
    ok, msg = m.spawn_in_terminal(CMD, {"DISPLAY": ":0", "XDG_CURRENT_DESKTOP": "X-Cinnamon"}, None, which_all,
                                  popen=lambda argv, **kw: calls.append((argv, kw)))
    assert ok and calls[0][0][:3] == ["gnome-terminal", "--maximize", "--"] and calls[0][1]["start_new_session"]
    ok, msg = m.spawn_in_terminal(CMD, {}, None, which_all, popen=lambda *a, **k: 1 / 0)
    assert not ok and "DISPLAY" in msg
    ok, msg = m.spawn_in_terminal(CMD, {"DISPLAY": ":0"}, None, lambda n: None, popen=lambda *a, **k: 1 / 0)
    assert not ok and "no supported terminal" in msg


def test_plan_with_windowid():
    steps, warn = m.plan_inplace({"DISPLAY": ":0", "WINDOWID": "41943047", "TERM": "xterm-256color"}, which_all)
    names = [s[0] for s in steps]
    assert names == ["wmctrl-windowid", "wmctrl-active", "xdotool-windowstate", "xdotool-size", "csi-9-1t"]
    assert steps[0][1] == ["wmctrl", "-i", "-r", "0x2800007", "-b", "add,maximized_vert,maximized_horz"]
    assert steps[2][1][-1] == "41943047" and warn is None


def test_plan_without_windowid_vte():
    steps, _ = m.plan_inplace({"DISPLAY": ":0", "TERM": "xterm-256color", "VTE_VERSION": "6800"}, which_all)
    assert [s[0] for s in steps] == ["wmctrl-active", "xdotool-windowstate", "xdotool-size"]  # VTE ignores CSI 9t
    assert steps[0][1] == ["wmctrl", "-r", ":ACTIVE:", "-b", "add,maximized_vert,maximized_horz"]
    assert steps[1][1][:2] == ["xdotool", "getactivewindow"]


def test_plan_fallbacks():
    steps, warn = m.plan_inplace({"DISPLAY": ":0", "TERM": "xterm"}, lambda n: None)
    assert [s[0] for s in steps] == ["csi-9-1t"] and steps[0][1] is None
    steps, warn = m.plan_inplace({"TERM": "linux"}, which_all)
    assert steps == [] and "no maximise method" in warn
    steps, warn = m.plan_inplace({"WAYLAND_DISPLAY": "wayland-0", "XDG_SESSION_TYPE": "wayland", "DISPLAY": ":0"}, which_all)
    assert steps == [] and "Wayland" in warn
    steps, _ = m.plan_inplace({"DISPLAY": ":0", "WINDOWID": "junk", "TERM": "xterm"}, which_all)
    assert "wmctrl-windowid" not in [s[0] for s in steps]


def test_recover_gui_env(tmp_path):
    # pid 300 (sudo) -> parent 200 (bash with DISPLAY) -> 1
    for pid, ppid, env in [(300, 200, b"PATH=/usr/bin\0"), (200, 1, b"DISPLAY=:0\0XAUTHORITY=/home/dan/.Xauthority\0WINDOWID=123\0")]:
        d = tmp_path / str(pid)
        d.mkdir()
        (d / "environ").write_bytes(env)
        (d / "stat").write_text("%d (x y) S %d 0 0" % (pid, ppid))
    out = m.recover_gui_env({"PATH": "/sbin"}, proc=str(tmp_path), start_pid=300)
    assert out["DISPLAY"] == ":0" and out["XAUTHORITY"] == "/home/dan/.Xauthority" and out["WINDOWID"] == "123"
    assert out["PATH"] == "/sbin"
    keep = m.recover_gui_env({"DISPLAY": ":5"}, proc=str(tmp_path), start_pid=300)
    assert keep["DISPLAY"] == ":5"


def test_forward_args():
    import netmon_tui
    argv = ["--spawn", "--sudo", "--terminal", "xterm", "--dry-run", "--terminal=kitty", "--deny", "x*.service"]
    assert netmon_tui.forward_args(argv, add=["--no-spawn"]) == ["--dry-run", "--deny", "x*.service", "--no-spawn"]


def test_maximise_inplace_stops_at_first_verified(monkeypatch):
    ran = []
    monkeypatch.setattr(m, "_run", lambda argv, env, timeout=3.0: (ran.append(argv) or (0, "")))
    states = iter([False, True, True])
    monkeypatch.setattr(m, "window_maximised", lambda env, wid, which=None: next(states))
    rep = m.maximise_inplace({"DISPLAY": ":0", "TERM": "xterm"}, which_all, tty_path="/nonexistent", settle=0.2)
    assert rep == ["maximise: OK via wmctrl-active"] and len(ran) == 1


def test_maximise_inplace_falls_through(monkeypatch):
    ran = []
    monkeypatch.setattr(m, "_run", lambda argv, env, timeout=3.0: (ran.append(argv[0]) or (1, "no WM")))
    monkeypatch.setattr(m, "window_maximised", lambda env, wid, which=None: False)
    rep = m.maximise_inplace({"DISPLAY": ":0", "TERM": "xterm-256color"}, which_all, tty_path="/nonexistent", settle=0.05)
    assert ran == ["wmctrl", "xdotool", "xdotool"] and all("failed" in r for r in rep)
