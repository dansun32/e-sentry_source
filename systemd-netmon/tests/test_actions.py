import json
import os
import pytest
from netmonlib import actions
from netmonlib.actions import ActionError, AuditLog, Executor, Policy, build_unit_command, validate_unit
from test_parsers import make_fake_proc


@pytest.mark.parametrize("u", ["ssh.service", "getty@tty1.service", "systemd-fsck@dev-disk-by\\x2duuid-AB12.service",
                               "cups.socket", "apt-daily.timer", "user@1000.service"])
def test_valid_units(u):
    assert validate_unit(u)


@pytest.mark.parametrize("u", ["", "-rf.service", "--now.service", "ssh", "ssh.service; rm -rf /", "a b.service",
                               "../../etc/passwd.service", "ssh.service\n", "x.mount", "x.target", None, 5, "a" * 300 + ".service"])
def test_invalid_units(u):
    assert not validate_unit(u)


def test_command_building():
    B = ["systemctl", "--no-ask-password"]
    assert build_unit_command("stop", "cups.service") == B + ["stop", "--", "cups.service"]
    assert build_unit_command("kill", "cups.service", "SIGKILL") == B + ["kill", "--signal=SIGKILL", "--", "cups.service"]
    assert build_unit_command("kill", "cups.service") == B + ["kill", "--signal=SIGTERM", "--", "cups.service"]
    assert build_unit_command("disable", "cups.service", now=True) == B + ["disable", "--now", "--", "cups.service"]
    assert build_unit_command("mask", "cups.service") == B + ["mask", "--", "cups.service"]
    assert build_unit_command("ipaccounting", "cups.service") == B + ["set-property", "--runtime", "--", "cups.service", "IPAccounting=yes"]
    assert actions.build_pid_command(1234, "SIGKILL") == ["kill", "-KILL", "1234"]
    for bad in [("reboot", "cups.service", None), ("kill", "cups.service", "SIGHUP"), ("stop", "bad name", None)]:
        with pytest.raises(ValueError):
            build_unit_command(*bad)


def test_denylist():
    p = Policy(ssh_check=lambda: False, extra=["docker*.service"], self_unit="mynetmon.service")
    for u in ["systemd-journald.service", "dbus.service", "systemd-logind.service", "systemd-udevd.service",
              "NetworkManager.service", "lightdm.service", "polkit.service", "piavpn.service", "ufw.service",
              "user@1000.service", "docker.service", "mynetmon.service", "systemd-netmon.service"]:
        assert p.check_unit("stop", u), u
    assert p.check_unit("stop", "cups.service") is None
    assert p.check_unit("start", "NetworkManager.service") is None  # non-destructive allowed
    assert p.check_unit("ipaccounting", "piavpn.service") is None
    assert p.check_unit("stop", "ssh.service") is None
    assert Policy(ssh_check=lambda: True).check_unit("stop", "ssh.service")


def test_ssh_detection(tmp_path):
    proc = make_fake_proc(tmp_path, {700: ("sshd", [], "", 1)})
    assert not actions.ssh_session_active(proc)
    (tmp_path / "proc/701").mkdir()
    (tmp_path / "proc/701/cmdline").write_bytes(b"sshd: dan@pts/0\0")
    assert actions.ssh_session_active(proc)


class Recorder:
    def __init__(self, rc=0):
        self.calls, self.rc = [], rc

    def __call__(self, cmd, timeout=0):
        self.calls.append(list(cmd))
        return self.rc, "out", "" if self.rc == 0 else "Failed to stop x: Access denied"


def mk(tmp_path, **kw):
    rec = Recorder(kw.pop("rc", 0))
    log = str(tmp_path / "audit.log")
    ex = Executor(Policy(ssh_check=lambda: False), AuditLog(log), runner=rec, **kw)
    return ex, rec, log


def audit(log):
    return [json.loads(l) for l in open(log)]


def test_dry_run_never_executes(tmp_path):
    ex, rec, log = mk(tmp_path, dry_run=True)
    r = ex.run_unit("mask", "cups.service", client="t")
    assert r["dry_run"] and r["cmd"][-1] == "cups.service" and rec.calls == []
    a = audit(log)[-1]
    assert a["result"] == "dry-run" and a["cmd"] == r["cmd"] and a["client"] == "t"
    assert oct(os.stat(log).st_mode & 0o777) == "0o600"


def test_live_execution_and_errors(tmp_path):
    ex, rec, log = mk(tmp_path)
    r = ex.run_unit("stop", "cups.service")
    assert r["ok"] and rec.calls == [["systemctl", "--no-ask-password", "stop", "--", "cups.service"]]
    (tmp_path / "b").mkdir()
    ex2, rec2, log2 = mk(tmp_path / "b", rc=1)
    r2 = ex2.run_unit("stop", "cups.service")
    assert not r2["ok"] and "Access denied" in r2["message"] and audit(log2)[-1]["result"] == "error"


def test_denylisted_requires_force(tmp_path):
    ex, rec, log = mk(tmp_path)
    with pytest.raises(ActionError) as e:
        ex.run_unit("kill", "piavpn.service", "SIGKILL")
    assert e.value.status == 403 and e.value.extra["requires_force"] and rec.calls == []
    assert audit(log)[-1]["result"] == "refused"
    with pytest.raises(ActionError):
        ex.run_unit("stop", "piavpn.service", force="true")  # must be boolean True, not truthy
    r = ex.run_unit("stop", "piavpn.service", force=True)
    assert r["ok"] and audit(log)[-1]["forced"] is True


def test_read_only(tmp_path):
    ex, rec, log = mk(tmp_path, read_only=True)
    with pytest.raises(ActionError) as e:
        ex.run_unit("stop", "cups.service")
    assert e.value.status == 403 and rec.calls == []
    with pytest.raises(ActionError):
        ex.kill_pid(5000, 1, "SIGTERM")


def test_invalid_unit_logged(tmp_path):
    ex, rec, log = mk(tmp_path)
    with pytest.raises(ActionError) as e:
        ex.run_unit("stop", "x.service; reboot")
    assert e.value.status == 400 and audit(log)[-1]["result"] == "invalid" and rec.calls == []


def pid_exec(tmp_path, **kw):
    proc = make_fake_proc(tmp_path, {
        4242: ("tcpdump", [51209], "0::/user.slice/session-2.scope\n", 3000),
        482: ("NetworkManager", [29041], "0::/system.slice/NetworkManager.service\n", 1),
        77: ("kworker/0:1", [], "0::/\n", 2),
    })
    killed = []
    log = str(tmp_path / "audit.log")
    ex = Executor(Policy(ssh_check=lambda: False), AuditLog(log), runner=Recorder(), proc=proc,
                  killer=lambda pid, sig: killed.append((pid, sig)), **kw)
    return ex, killed, log


def test_kill_pid_paths(tmp_path):
    import signal
    ex, killed, log = pid_exec(tmp_path)
    r = ex.kill_pid(4242, 51209, "SIGKILL")
    assert r["ok"] and killed == [(4242, signal.SIGKILL)] and r["cmd"] == ["kill", "-KILL", "4242"]
    for pid, inode, status in [(1, 1, 403), (os.getpid(), 1, 403), (77, 1, 403), (99999, 1, 404),
                               (4242, 29041, 409), (4242, None, 400), ("4242", 51209, 400), (True, 1, 400)]:
        with pytest.raises(ActionError) as e:
            ex.kill_pid(pid, inode, "SIGTERM")
        assert e.value.status == status, (pid, inode)
    with pytest.raises(ActionError):
        ex.kill_pid(4242, 51209, "SIGHUP")
    # PID belonging to a protected unit needs force
    with pytest.raises(ActionError) as e:
        ex.kill_pid(482, 29041, "SIGTERM")
    assert e.value.extra["requires_force"]
    assert ex.kill_pid(482, 29041, "SIGTERM", force=True)["ok"]
    assert len(killed) == 2
    results = [a["result"] for a in audit(log)]
    assert results.count("ok") == 2 and results.count("refused") >= 9


def test_kill_pid_dry_run(tmp_path):
    ex, killed, log = pid_exec(tmp_path, dry_run=True)
    r = ex.kill_pid(4242, 51209, "SIGTERM")
    assert r["dry_run"] and killed == [] and audit(log)[-1]["result"] == "dry-run"
    p = ex.preview_pid(482, 29041, "SIGTERM")
    assert p["requires_force"] and p["unit"] == "NetworkManager.service"
