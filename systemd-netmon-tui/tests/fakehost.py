"""Fake host for offline UI tests / screenshots: stub `systemctl` on PATH + fake /proc tree.
Run:  python3 tests/fakehost.py [netmon_tui args...]   (always --dry-run, audit to $FAKEHOST_AUDIT)"""
import os, pathlib, sys, tempfile
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE)); sys.path.insert(0, HERE)

STUB = r'''#!/usr/bin/env python3
import sys, time
FIX = %r
a = sys.argv[1:]
t = time.time()
def blk(unit, desc, act, sub, uf, acct, i=0, o=0):
    v = (lambda n: str(int(n))) if acct else (lambda n: "[not set]")
    return ("Id=%%s\nDescription=%%s\nLoadState=loaded\nActiveState=%%s\nSubState=%%s\nUnitFileState=%%s\nMainPID=1\n"
            "IPAccounting=%%s\nIPIngressBytes=%%s\nIPEgressBytes=%%s\nIPIngressPackets=%%s\nIPEgressPackets=%%s\n\n"
            %% (unit, desc, act, sub, uf, "yes" if acct else "no", v(i), v(o), v(i / 900), v(o / 900)))
UNITS = [("piavpn.service", "Private Internet Access daemon", "active", "running", "enabled", True, 5000, 1200),
         ("ssh.service", "OpenBSD Secure Shell server", "active", "running", "enabled", True, 300, 900),
         ("systemd-resolved.service", "Network Name Resolution", "active", "running", "enabled", True, 800, 400),
         ("cups.service", "CUPS Scheduler", "active", "running", "enabled", False, 0, 0),
         ("NetworkManager.service", "Network Manager", "active", "running", "enabled", False, 0, 0),
         ("avahi-daemon.service", "Avahi mDNS/DNS-SD Stack", "inactive", "dead", "masked", False, 0, 0),
         ("accounts-daemon.service", "Accounts Service", "failed", "failed", "enabled", False, 0, 0)]
if a[0] == "list-units":
    for u in UNITS: print("%%s loaded %%s %%s %%s" %% (u[0], u[2], u[3], u[1]))
elif a[0] == "show":
    for u in UNITS: sys.stdout.write(blk(u[0], u[1], u[2], u[3], u[4], u[5], 1e7 + (t %% 1e5) * u[6], 2e7 + (t %% 1e5) * u[7]))
'''


def setup(tmp=None):
    from test_parsers import make_fake_proc
    tmp = pathlib.Path(tmp or tempfile.mkdtemp(prefix="fakehost-"))
    bindir = tmp / "bin"; bindir.mkdir(exist_ok=True)
    (bindir / "systemctl").write_text(STUB % os.path.join(HERE, "fixtures"))
    (bindir / "systemctl").chmod(0o755)
    os.environ["PATH"] = str(bindir) + os.pathsep + os.environ["PATH"]
    proc = make_fake_proc(tmp, {
        482: ("NetworkManager", [29041, 51209], "0::/system.slice/NetworkManager.service\n", 1),
        912: ("dhclient", [18493], "0::/system.slice/NetworkManager.service\n", 482),
        4102: ("tcpdump", [34102, 34103], "0::/user.slice/session-2.scope\n", 3000)})
    return proc


def main(argv):
    proc = setup()
    from netmontui.actions import AuditLog, Executor, Policy
    from netmontui.systemd import Sampler
    from netmontui.ui import App
    color = argv[argv.index("--color") + 1] if "--color" in argv else "auto"
    s = Sampler(proc=proc, have_systemd=True, min_interval=0.1)
    ex = Executor(Policy(ssh_check=lambda: False), AuditLog(os.environ.get("FAKEHOST_AUDIT")), dry_run=True, proc=proc)
    App(s, ex, 0.5, color).run()


if __name__ == "__main__":
    main(sys.argv[1:])
