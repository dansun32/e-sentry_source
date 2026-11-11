# Linux downloads

Fetch only this folder:

```bash
git clone --depth 1 --filter=blob:none --sparse https://github.com/dansun32/e-sentry_source
cd e-sentry_source
git sparse-checkout set linux
cd linux
```

Three versions, all Python 3.10+ standard library only:

| Folder | What it is | Run |
|---|---|---|
| `systemd-netmon-live/` | Original page with live data, read-only | `sudo python3 netmon_live.py` then open http://127.0.0.1:8787/ |
| `systemd-netmon/` | Web app with stop/kill/disable/mask actions | `sudo python3 netmon.py --dry-run` (drop `--dry-run` for live actions); open the URL it prints |
| `systemd-netmon-tui/` | Terminal-only, self-maximising | `python3 netmon_tui.py --sudo` |

Each folder has its own README with all options.
