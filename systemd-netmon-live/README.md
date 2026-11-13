# systemd-netmon live (original page, real data)

Your original `systemd-netmon` mockup page, unchanged in look (same Tailwind/Lucide/Google
Fonts CDN links, header, panels, drawer, footer and keys), now fed with **real data** by a
tiny **read-only** Python helper (`netmon_live.py`, stdlib only, no actions, no POST).

## Install and run

The page is hosted on GitHub at **https://e-sentry.net/**; this helper feeds it live data from
`http://127.0.0.1:8787/api/data`. Chrome may ask to allow the site to access devices on your local
network: click **Allow**.

```
sudo apt update && sudo apt install -y python3 git
git clone --depth 1 --filter=blob:none --sparse https://github.com/dansun32/e-sentry_source
cd e-sentry_source
git sparse-checkout set linux
cd linux/systemd-netmon-live
sudo python3 netmon_live.py
```

To update later:

```
cd e-sentry_source && git pull
```

Without `sudo`, other users' raw/packet socket owners show "unknown". Options: `--port N`
(default 8787; then open `https://dansun32.github.io/e-sentry_source/?helper=N`), `--interval S`
(minimum seconds between real samples, default 0.25), `--allow-origin ORIGIN` (another site allowed
to read `/api/data`, repeatable). The page polls at its own 500/1000/2000 ms setting. The helper also
serves its own copy at http://127.0.0.1:8787/. Ctrl-C stops it.

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
listed with **n/a** (never invented).

> **Note:** These changes to IP accounting will not be persistent: enabling it with
> `systemctl set-property --runtime <unit> IPAccounting=yes` only lasts until the next reboot.
> A unit starts counting only after it restarts, so instead of rebooting you can restart just that service:
>
> ```
> sudo systemctl restart <unit>.service
> ```

**Raw socket columns relabelled:** the kernel keeps **no per-socket packet counters** for
raw/packet sockets. *Packet Rate* became **Drop Rate**: kernel drops per second for raw/raw6
sockets, n/a for packet sockets. *Cumulative Packets* became **Drops / Rmem**: cumulative
drops for raw sockets, receive-buffer bytes for packet sockets.

Keys are unchanged: **Space** pause/resume (the button now correctly returns to "PAUSE"),
**/** filter, **R** reset stats (client-side baseline; kernel counters untouched).

## Safety

Read-only by design: GET only (`/`, `/api/data`). Any POST/PUT/DELETE returns 405. It binds
127.0.0.1 only. The Host header must be `127.0.0.1:PORT` or `localhost:PORT`, which blocks
DNS rebinding. CORS headers are sent only for `GET /api/data` (and its preflight, including
Chrome's `Access-Control-Allow-Private-Network`) when the Origin is exactly
`https://dansun32.github.io`, `https://e-sentry.net`, `https://www.e-sentry.net` or one added with
`--allow-origin`, so other websites can't read the data. All
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
