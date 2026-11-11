# Improvements: IPAccounting notes for systemd-netmon

## Why not every unit shows traffic

The shipped default is **no**. In `/etc/systemd/system.conf` the line

```
#DefaultIPAccounting=no
```

is commented out. A commented line is systemd's way of showing the built-in default, not an active setting. So unless it is uncommented and set to `yes`, no service gets IP accounting automatically, and systemd-netmon shows those units as **n/a** (never invented numbers).

## Enabling accounting

```bash
sudo systemctl set-property --runtime ssh.service IPAccounting=yes   # until reboot
sudo systemctl set-property ssh.service IPAccounting=yes             # persistent
# all services: set DefaultIPAccounting=yes under [Manager] in /etc/systemd/system.conf, then:
sudo systemctl daemon-reexec
```

## If DefaultIPAccounting=yes is set but units still show n/a

- **Already-running services keep their old setting.** `daemon-reexec` makes systemd re-read the default, but it only applies when a unit starts. Services that were running before the change stay off until they are restarted or the machine reboots.
- **Leading `#` or a typo.** The line has to be uncommented and inside the `[Manager]` section.
- **Overridden elsewhere.** A file in `/etc/systemd/system.conf.d/` or `/usr/lib/systemd/system.conf.d/` can set it back, and a unit's own `IPAccounting=no` (or a drop-in) beats the default.
- **Some units never count.** The setting only covers units with a cgroup (services, sockets, slices, scopes). Processes in another network namespace or using raw sockets may not be counted as expected.
- **Counters reset** whenever a unit restarts, so a freshly restarted unit can briefly show zero.

## Diagnosis

```bash
systemctl show --property=DefaultIPAccounting
systemd-analyze cat-config systemd/system.conf | grep -i ipaccounting
systemctl show ssh.service -p IPAccounting -p IPIngressBytes
```

1. The first shows the value the running systemd is actually using.
2. The second lists every config file that sets it.
3. The third shows whether a given unit has accounting enabled, and its counter.

If (1) says `yes` but a unit says `no`, restart that unit (or reboot) to turn it on.
