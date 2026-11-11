#!/bin/sh
# Install the menu launcher for the current user (no root needed).
# usage: sh packaging/install-desktop.sh            (from the extracted folder)
set -eu
DIR=$(cd "$(dirname "$0")/.." && pwd)
DEST="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
mkdir -p "$DEST"
sed "s#@DIR@#$DIR#g" "$DIR/packaging/systemd-netmon-tui.desktop.in" > "$DEST/systemd-netmon-tui.desktop"
chmod 644 "$DEST/systemd-netmon-tui.desktop"
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$DEST" || true
echo "installed $DEST/systemd-netmon-tui.desktop  (Exec uses $DIR/netmon_tui.py)"
