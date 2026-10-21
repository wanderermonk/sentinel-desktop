#!/usr/bin/env bash
# Remove Sentinel and its login agent. Add --purge to also delete its data (baselines, history, policy).
set -uo pipefail
launchctl bootout "gui/$(id -u)/com.fighter.sentinel" 2>/dev/null
rm -f "$HOME/Library/LaunchAgents/com.fighter.sentinel.plist"
osascript -e 'quit app "Sentinel"' 2>/dev/null; sleep 2
pkill -f "Sentinel.app/Contents/MacOS/Sentinel" 2>/dev/null
rm -rf /Applications/Sentinel.app
if [[ "${1:-}" == "--purge" ]]; then
  rm -rf "$HOME/Library/Application Support/Sentinel"
  echo "Removed Sentinel and its data."
else
  echo "Removed Sentinel. Data kept in ~/Library/Application Support/Sentinel (use --purge to delete)."
fi
echo "Note: firewall (pf) rules Sentinel created are cleared on reboot, or remove them in Sentinel > Settings first."
