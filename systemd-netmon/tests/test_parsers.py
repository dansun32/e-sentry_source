import os
from conftest import fixture
from netmonlib import procnet, systemd


def test_parse_raw_ipv4():
    rows = procnet.parse_proc_net_raw(fixture("proc_net_raw.txt"), "raw")
    assert [r["inode"] for r in rows] == [29041, 18492]
    assert rows[0]["proto"] == "RAW ICMP" and rows[0]["local"] == "0.0.0.0"
    assert rows[1]["proto"] == "RAW RAW" and rows[1]["local"] == "127.0.0.1"
    assert rows[1]["uid"] == 1000 and rows[1]["drops"] == 17
    assert rows[1]["tx_queue"] == 0x10 and rows[1]["rx_queue"] == 0x200


def test_parse_raw6():
    rows = procnet.parse_proc_net_raw(fixture("proc_net_raw6.txt"), "raw6")
    assert rows[0]["local"] == "::1" and rows[0]["proto"] == "RAW6 ICMPv6" and rows[0]["drops"] == 3


def test_parse_packet():
    rows = procnet.parse_proc_net_packet(fixture("proc_net_packet.txt"), ifname=lambda i: "eth%d" % i)
    assert rows[0]["proto"] == "ETH_P_ALL (RAW)" and rows[0]["iface"] == "eth2"
    assert rows[1]["proto"] == "ETH_P_IP (DGRAM)" and rows[1]["iface"] == "any" and rows[1]["rmem"] == 4352
    assert rows[2]["proto"].startswith("ETH_P_PAE")
    assert all(r["drops"] is None for r in rows)


def test_parse_garbage_and_empty():
    assert procnet.parse_proc_net_raw("header\nnonsense line\n") == []
    assert procnet.parse_proc_net_packet("") == []


def test_cgroup_unit():
    assert procnet.parse_cgroup_unit(fixture("cgroup_v2.txt")) == "NetworkManager.service"
    assert procnet.parse_cgroup_unit(fixture("cgroup_v1.txt")) == "piavpn.service"
    assert procnet.parse_cgroup_unit("0::/user.slice/user-1000.slice/session-2.scope\n") == "session-2.scope"
    assert procnet.parse_cgroup_unit("0::/\n") is None


def make_fake_proc(tmp_path, procs):
    """procs: {pid: (comm, [inodes], cgroup_text, ppid)}"""
    root = tmp_path / "proc"
    (root / "net").mkdir(parents=True)
    (root / "net/raw").write_text(fixture("proc_net_raw.txt"))
    (root / "net/raw6").write_text(fixture("proc_net_raw6.txt"))
    (root / "net/packet").write_text(fixture("proc_net_packet.txt"))
    for pid, (comm, inodes, cg, ppid) in procs.items():
        d = root / str(pid)
        (d / "fd").mkdir(parents=True)
        (d / "comm").write_text(comm + "\n")
        (d / "cgroup").write_text(cg)
        (d / "status").write_text("Name:\t%s\nPPid:\t%d\n" % (comm, ppid))
        (d / "cmdline").write_bytes(comm.encode() + b"\0")
        for i, ino in enumerate(inodes):
            os.symlink("socket:[%d]" % ino, str(d / "fd" / str(i + 3)))
        os.symlink("/dev/null", str(d / "fd" / "0"))
    return str(root)


def test_inode_mapping_and_collect(tmp_path):
    proc = make_fake_proc(tmp_path, {
        482: ("NetworkManager", [29041, 51209], "0::/system.slice/NetworkManager.service\n", 1),
        912: ("dhclient", [18493], "0::/system.slice/NetworkManager.service\n", 482),
        4102: ("tcpdump", [99999], "0::/user.slice/session-2.scope\n", 3000),
    })
    m, complete = procnet.map_socket_inodes(None, proc)
    assert m[29041] == [482] and m[18493] == [912] and complete
    socks, complete = procnet.collect_sockets(proc)
    by = {s["inode"]: s for s in socks}
    assert by[29041]["process"] == "NetworkManager" and by[29041]["pid"] == 482
    assert by[29041]["unit"] == "NetworkManager.service"
    assert by[18492]["pid"] is None and by[18492]["process"] is None  # unowned/unknown
    assert all(s["packets"] is None and s["packet_rate"] is None for s in socks)  # never faked
    assert procnet.pid_has_inode(482, 51209, proc) and not procnet.pid_has_inode(482, 18493, proc)


def test_parse_counter():
    assert systemd.parse_counter("123") == 123
    assert systemd.parse_counter("[not set]") is None
    assert systemd.parse_counter(str(2 ** 64 - 1)) is None
    assert systemd.parse_counter("") is None and systemd.parse_counter(None) is None


def test_parse_show_records():
    recs = [systemd.unit_record(b) for b in systemd.parse_show(fixture("systemctl_show.txt"))]
    assert [r["unit"] for r in recs] == ["ssh.service", "cups.service", "avahi-daemon.service"]
    ssh, cups, avahi = recs
    assert ssh["ip_accounting"] and ssh["in_bytes"] == 8900400 and ssh["out_packets"] == 9001
    assert cups["in_bytes"] is None and not cups["ip_accounting"]
    assert avahi["in_bytes"] is None and avahi["unit_file_state"] == "masked" and avahi["main_pid"] == 0


def test_parse_list_units():
    units = systemd.parse_list_units(fixture("systemctl_list_units.txt"))
    assert units[0] == {"unit": "accounts-daemon.service", "load": "loaded", "active": "active",
                        "sub": "running", "description": "Accounts Service"}
    assert systemd.parse_list_units("● foo.service not-found inactive dead foo.service")[0]["unit"] == "foo.service"


class FakeSystemctl:
    def __init__(self):
        self.ing = 1000
        self.calls = []

    def __call__(self, cmd, timeout=0):
        self.calls.append(list(cmd))
        if cmd[1] == "list-units":
            return 0, fixture("systemctl_list_units.txt"), ""
        if cmd[1] == "list-unit-files":
            return 0, "masked-thing.service masked enabled\n", ""
        if cmd[1] == "show":
            txt = fixture("systemctl_show.txt").replace("IPIngressBytes=8900400", "IPIngressBytes=%d" % self.ing)
            return 0, txt, ""
        return 1, "", "unexpected"


def test_sampler_rates(tmp_path):
    proc = make_fake_proc(tmp_path, {})
    clock = [100.0]
    fake = FakeSystemctl()
    s = systemd.Sampler(runner=fake, min_interval=0, proc=proc, clock=lambda: clock[0], have_systemd=True)
    snap1 = s.sample()
    ssh = [u for u in snap1["services"] if u["unit"] == "ssh.service"][0]
    assert ssh["in_bps"] is None  # first sample: no rate yet
    show = [c for c in fake.calls if c[1] == "show"][0]
    assert "foo.service" not in show and "masked-thing.service" in show  # not-found skipped, masked added
    fake.ing += 2048
    clock[0] += 2.0
    snap2 = s.sample()
    ssh = [u for u in snap2["services"] if u["unit"] == "ssh.service"][0]
    cups = [u for u in snap2["services"] if u["unit"] == "cups.service"][0]
    assert ssh["in_bps"] == 1024.0 and ssh["out_bps"] == 0.0 and ssh["history"] == [1024.0]
    assert cups["in_bps"] is None and cups["accounting_active"] is False
    assert snap2["totals"]["in_bps"] == 1024.0 and snap2["totals"]["accounting_units"] == 1
    fake.ing = 5  # counter reset (unit restarted) -> n/a rather than negative
    clock[0] += 1.0
    ssh = [u for u in s.sample()["services"] if u["unit"] == "ssh.service"][0]
    assert ssh["in_bps"] is None


def test_sampler_without_systemd(tmp_path):
    s = systemd.Sampler(runner=lambda c, t=0: (1, "", ""), proc=make_fake_proc(tmp_path, {}), have_systemd=False)
    snap = s.sample()
    assert snap["services"] == [] and not snap["systemd_available"] and snap["systemd_error"]
    assert snap["totals"]["sockets"] == 6
