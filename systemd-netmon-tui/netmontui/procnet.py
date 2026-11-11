"""Parsers for /proc/net/{raw,raw6,packet} and inode -> PID/process mapping.

Honesty note: the kernel does NOT expose per-socket packet counters for raw or
packet sockets in /proc.  We therefore report packet counts as None ("n/a") and
only show what really exists: the `drops` counter (raw/raw6), rx/tx queue bytes
(raw/raw6) and Rmem (packet).
"""
from __future__ import annotations

import os
import socket
import struct
from typing import Dict, Iterable, List, Optional, Tuple

PROC = "/proc"

IP_PROTOS = {
    0: "IP", 1: "ICMP", 2: "IGMP", 4: "IPIP", 6: "TCP", 17: "UDP", 41: "IPv6",
    47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6", 89: "OSPF", 103: "PIM",
    112: "VRRP", 132: "SCTP", 255: "RAW",
}

ETH_P = {
    0x0000: "none (unbound)", 0x0001: "ETH_P_802_3", 0x0003: "ETH_P_ALL",
    0x0004: "ETH_P_802_2", 0x0019: "ETH_P_80211_RAW", 0x0800: "ETH_P_IP",
    0x0806: "ETH_P_ARP", 0x86DD: "ETH_P_IPV6", 0x888E: "ETH_P_PAE (EAPOL)",
    0x88CC: "ETH_P_LLDP", 0x8100: "ETH_P_8021Q", 0x8863: "ETH_P_PPP_DISC",
    0x8864: "ETH_P_PPP_SES", 0x88F7: "ETH_P_1588 (PTP)",
}

PACKET_SOCK_TYPES = {1: "STREAM", 2: "DGRAM", 3: "RAW", 10: "PACKET"}


def _hex_ipv4(h: str) -> str:
    return socket.inet_ntop(socket.AF_INET, struct.pack("<I", int(h, 16)))


def _hex_ipv6(h: str) -> str:
    # 4 x 32-bit words, each printed in host (little-endian) order
    raw = b"".join(struct.pack("<I", int(h[i:i + 8], 16)) for i in range(0, 32, 8))
    return socket.inet_ntop(socket.AF_INET6, raw)


def parse_proc_net_raw(text: str, family: str = "raw") -> List[dict]:
    """Parse /proc/net/raw (family='raw') or /proc/net/raw6 (family='raw6')."""
    out = []
    for line in text.splitlines()[1:]:
        f = line.split()
        if len(f) < 10:
            continue
        try:
            laddr, lport = f[1].split(":")
            raddr, _ = f[2].split(":")
            tx_q, rx_q = f[4].split(":")
            proto = int(lport, 16)  # for raw sockets the "port" is the IP protocol
            dec = _hex_ipv6 if family == "raw6" else _hex_ipv4
            out.append({
                "kind": family,
                "inode": int(f[9]),
                "uid": int(f[7]),
                "proto_num": proto,
                "proto": "%s %s" % ("RAW6" if family == "raw6" else "RAW",
                                     IP_PROTOS.get(proto, "proto %d" % proto)),
                "local": dec(laddr),
                "remote": dec(raddr),
                "tx_queue": int(tx_q, 16),
                "rx_queue": int(rx_q, 16),
                "drops": int(f[12]) if len(f) > 12 else None,
                "iface": None,
            })
        except (ValueError, IndexError, OSError):
            continue
    return out


def parse_proc_net_packet(text: str, ifname=None) -> List[dict]:
    """Parse /proc/net/packet. Columns: sk RefCnt Type Proto Iface R Rmem User Inode."""
    ifname = ifname or _ifname
    out = []
    for line in text.splitlines()[1:]:
        f = line.split()
        if len(f) < 9:
            continue
        try:
            stype = int(f[2])
            proto = int(f[3], 16)
            ifidx = int(f[4])
            out.append({
                "kind": "packet",
                "inode": int(f[8]),
                "uid": int(f[7]),
                "proto_num": proto,
                "proto": "%s (%s)" % (ETH_P.get(proto, "0x%04x" % proto),
                                      PACKET_SOCK_TYPES.get(stype, "type %d" % stype)),
                "iface": ifname(ifidx) if ifidx else "any",
                "running": f[5] == "1",
                "rmem": int(f[6]),
                "drops": None,
                "rx_queue": None,
                "tx_queue": None,
            })
        except (ValueError, IndexError):
            continue
    return out


def _ifname(idx: int) -> str:
    try:
        return socket.if_indextoname(idx)
    except OSError:
        return "if#%d" % idx


def read_text(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def read_comm(pid: int, proc: str = PROC) -> str:
    return read_text(os.path.join(proc, str(pid), "comm")).strip() or "?"


def parse_cgroup_unit(text: str) -> Optional[str]:
    """Return the systemd unit (service/scope) owning a process from /proc/PID/cgroup."""
    for line in text.splitlines():
        parts = line.split(":", 2)
        if len(parts) != 3:
            continue
        if parts[0] == "0" or parts[1] == "name=systemd":
            segs = [s for s in parts[2].split("/") if s]
            for seg in reversed(segs):
                if seg.endswith(".service") or seg.endswith(".scope"):
                    return seg
    return None


def pid_unit(pid: int, proc: str = PROC) -> Optional[str]:
    return parse_cgroup_unit(read_text(os.path.join(proc, str(pid), "cgroup")))


def map_socket_inodes(wanted: Optional[Iterable[int]] = None, proc: str = PROC
                      ) -> Tuple[Dict[int, List[int]], bool]:
    """Scan /proc/*/fd for socket:[inode] links.

    Returns ({inode: [pid, ...]}, complete) where complete=False means some
    processes' fds could not be read (not running as root).
    """
    want = set(wanted) if wanted is not None else None
    result: Dict[int, List[int]] = {}
    complete = True
    try:
        pids = [d for d in os.listdir(proc) if d.isdigit()]
    except OSError:
        return result, False
    for d in pids:
        fd_dir = os.path.join(proc, d, "fd")
        try:
            fds = os.listdir(fd_dir)
        except PermissionError:
            complete = False
            continue
        except OSError:
            continue
        for fd in fds:
            try:
                link = os.readlink(os.path.join(fd_dir, fd))
            except OSError:
                continue
            if link.startswith("socket:["):
                try:
                    ino = int(link[8:-1])
                except ValueError:
                    continue
                if want is None or ino in want:
                    lst = result.setdefault(ino, [])
                    if int(d) not in lst:
                        lst.append(int(d))
    return result, complete


def pid_has_inode(pid: int, inode: int, proc: str = PROC) -> bool:
    fd_dir = os.path.join(proc, str(pid), "fd")
    try:
        for fd in os.listdir(fd_dir):
            try:
                if os.readlink(os.path.join(fd_dir, fd)) == "socket:[%d]" % inode:
                    return True
            except OSError:
                continue
    except OSError:
        return False
    return False


def collect_sockets(proc: str = PROC) -> Tuple[List[dict], bool]:
    """Return (sockets, pid_mapping_complete). Each socket gets pids/procs/unit."""
    socks = (parse_proc_net_raw(read_text(os.path.join(proc, "net/raw")), "raw")
             + parse_proc_net_raw(read_text(os.path.join(proc, "net/raw6")), "raw6")
             + parse_proc_net_packet(read_text(os.path.join(proc, "net/packet"))))
    complete = True
    if socks:
        imap, complete = map_socket_inodes({s["inode"] for s in socks}, proc)
    else:
        imap = {}
    for s in socks:
        pids = sorted(imap.get(s["inode"], []))
        s["pids"] = pids
        s["pid"] = pids[0] if pids else None
        s["process"] = read_comm(pids[0], proc) if pids else None
        s["unit"] = pid_unit(pids[0], proc) if pids else None
        s["packets"] = None          # not exposed by the kernel per socket
        s["packet_rate"] = None
    return socks, complete
