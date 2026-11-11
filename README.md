# e-sentry_source

Network service monitor ("What Is Running"): the original systemd-netmon page mockup plus working Linux and Windows versions.

## Download just the part you need

```
git clone --depth 1 --filter=blob:none --sparse https://github.com/dansun32/e-sentry_source
cd e-sentry_source
git sparse-checkout set linux      # or: windows
```

- [`linux/`](linux/INSTALL.md): live web page (read-only), web app with actions, and terminal UI.
- [`windows/`](windows/INSTALL.md): Windows port with prebuilt ETW (C#) and raw/WFP (C++) helpers.

## Source

- `systemd-netmon-live/`, `systemd-netmon/`, `systemd-netmon-tui/`: Linux versions with tests.
- `netmon-win/`: Windows port source, tests, build scripts (`build.ps1`, `build-cross.sh`) and a GitHub Actions workflow.
- `systemd_network_monitor.html`, `systemd_network_monitor_terminal.html`, `WHAT IS RUNNING`: original mockups.
- `improvements.md`, `win_port.md`: design notes.
