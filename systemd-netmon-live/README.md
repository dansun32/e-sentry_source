# systemd-netmon live (original page, real data)

Your original `systemd-netmon` mockup page, unchanged in look (same Tailwind/Lucide/Google
Fonts CDN links, header, panels, drawer, footer and keys), now fed with **real data** by a
tiny **read-only** Python helper (`netmon_live.py`, stdlib only, no actions, no POST).

## Install and run

```bash
mkdir -p ~/systemd-netmon-live
tar -xzf ~/.grok_exports/systemd-netmon-live.tgz -C ~/systemd-netmon-live --strip-components=1
cd ~/systemd-netmon-live
python3 netmon_live.py           # no root: other users' raw/packet socket owners show "unknown"
sudo python3 netmon_live.py      # root: every socket mapped to its process
```
Then open **http://127.0.0.1:8787/**. Options: `--port N` (default 8787),
`--interval S` (minimum seconds between real samples, default 0.25). The page polls at its own
500/1000/2000 ms setting. Ctrl-C stops it.

## Firewall / CDN

* The helper only listens on 127.0.0.1, so your raw-table DROP-by-default rules must allow
  loopback (`-i lo` / `-o lo` ACCEPT), or the page won't load.
* The page still loads Tailwind (`cdn.tailwindcss.com`), Lucide (`unpkg.com`) and JetBrains
  Mono (`fonts.googleapis.com`) from the internet, exactly like the mockup. If your
  firewall/killswitch blocks them, the page still works and shows live data, but **unstyled**
  (plain text layout, no icons). (Tested: see `screenshot-cdn-blocked.png`.)

## What's real now

| Element | Source |
|---|---|
| Services list | running `.service` units (`systemctl list-units --state=running`) |
| Throughput, In / Out rate | separate deltas of `IPIngressBytes` / `IPEgressBytes` between polls (was a fake 40/60 split) |
| Total data | `IPIngressBytes + IPEgressBytes` (minus your Reset baseline) |
| Sparkline | last 10 of the helper's per-unit rate history |
| Systemd total ingress / egress | sum of the real per-unit rates |
| Active Monitored Units | `monitored / running` (monitored = IPAccounting on) |
| Raw sockets list | `/proc/net/raw`, `raw6`, `packet`; inode → PID → process via `/proc/*/fd` |
| OS / kernel in header | `/etc/os-release` + `uname` from the helper |
| Status text | `LIVE D-BUS POLLING`, `PAUSED`, or red `HELPER UNREACHABLE` |

**IPAccounting:** byte counters exist only for units with `IPAccounting=yes`. Others are
listed with **n/a** (never invented). To enable one:
```bash
sudo systemctl set-property --runtime ssh.service IPAccounting=yes   # until reboot
sudo systemctl set-property ssh.service IPAccounting=yes             # persistent
# all services: DefaultIPAccounting=yes in /etc/systemd/system.conf, then sudo systemctl daemon-reexec
```

**Raw socket columns relabelled:** the kernel keeps **no per-socket packet counters** for
raw/packet sockets. *Packet Rate* became **Drop Rate**: kernel drops per second for raw/raw6
sockets, n/a for packet sockets. *Cumulative Packets* became **Drops / Rmem**: cumulative
drops for raw sockets, receive-buffer bytes for packet sockets.

Keys are unchanged: **Space** pause/resume (the button now correctly returns to "PAUSE"),
**/** filter, **R** reset stats (client-side baseline; kernel counters untouched).

## Safety

Read-only by design: GET only (`/`, `/api/data`). Any POST/PUT/DELETE returns 405. It binds
127.0.0.1 only. The Host header must be `127.0.0.1:PORT` or `localhost:PORT`, which blocks
DNS rebinding. No CORS headers are sent, so other websites can't read the data. All
data the page inserts as HTML is escaped (process names can contain markup).

## Files

```
netmon_live.py     helper (stdlib, read-only)
netmon.html        the original page with the data script swapped in, plus the setup modal
original.html      the untouched original, for reference
index.html.diff    unified diff original -> live
tests/             pytest (JSON shape, rates, HTTP rules) + fakehost_server.py demo
```
Tests: `python3 -m pytest -q tests` (needs python3-pytest; fully offline).
