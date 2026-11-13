# Linux: install the local helper

The dashboard runs on GitHub at **https://e-sentry.net/**. You only install the small local helper;
it feeds live data into that page from `http://127.0.0.1:8787/api/data`. Chrome may ask to allow the
site to access devices on your local network: click **Allow**.

```
sudo apt update && sudo apt install -y python3 git
git clone --depth 1 --filter=blob:none --sparse https://github.com/dansun32/e-sentry_source
cd e-sentry_source
git sparse-checkout set linux
cd linux/systemd-netmon-live
sudo python3 netmon_live.py --background
```

`sudo python3 netmon_live.py --background` checks that it can start, then runs in the background and
returns you to the prompt (`sudo` still asks for your password first). If something is wrong, the error
stays on screen and nothing is left running. To stop it (from `linux/systemd-netmon-live`):

```
sudo python3 netmon_live.py --stop
```

`--status` says whether it is running. The log is `/var/log/e-sentry-helper.log` and the PID file
`/run/e-sentry-helper.pid` (when run with sudo). Leave out `--background` to run it in the
terminal instead (Ctrl-C stops it).

To update later:

```
cd e-sentry_source && git pull
```

> **Note:** These changes to IP accounting will not be persistent: enabling it with
> `systemctl set-property --runtime <unit> IPAccounting=yes` only lasts until the next reboot.
> A unit starts counting only after it restarts, so instead of rebooting you can restart just that service:
>
> ```
> sudo systemctl restart <unit>.service
> ```

Needs systemd and Python 3 (standard library only). Without `sudo` the helper still runs, but
other users' raw/packet sockets show their owner as "unknown". With a non-default `--port N`, open
`https://dansun32.github.io/e-sentry_source/?helper=N`.

The helper is read-only, listens on 127.0.0.1 only, and shares `/api/data` only with
https://dansun32.github.io, https://e-sentry.net and https://www.e-sentry.net (add more with
`--allow-origin`).

## Other Linux versions in this folder

| Folder | What it is | Run |
|---|---|---|
| `systemd-netmon-live/` | Live data helper for the hosted dashboard, read-only | `sudo python3 netmon_live.py --background` (stop: `--stop`) |
| `systemd-netmon/` | Web app with stop/kill/disable/mask actions (runs locally) | `sudo python3 netmon.py --dry-run` (drop `--dry-run` for live actions); open the URL it prints |
| `systemd-netmon-tui/` | Terminal-only, self-maximising | `python3 netmon_tui.py --sudo` |

Each folder has its own README with all options.
