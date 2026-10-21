#!/usr/bin/env bash
# One-command install on macOS: builds Sentinel, installs it to /Applications and turns on
# always-on monitoring (starts at every login, relaunches itself if it crashes, resumes after sleep).
#   bash scripts/install_mac.sh
set -euo pipefail
cd "$(dirname "$0")/.."

[[ "$(uname)" == "Darwin" ]] || { echo "This installer is for macOS."; exit 1; }
command -v python3 >/dev/null || { echo "python3 is required (brew install python)"; exit 1; }
command -v npm >/dev/null     || { echo "Node.js/npm is required (brew install node)"; exit 1; }

echo "==> Installing build tools"
npm install

echo "==> Building engine + app (takes a few minutes)"
export CSC_IDENTITY_AUTO_DISCOVERY=false        # local, unsigned build
npm run dist:mac

APP="$(ls -d dist/mac*/Sentinel.app 2>/dev/null | head -1)"
[[ -d "$APP" ]] || { echo "Build finished but Sentinel.app was not found in dist/"; exit 1; }

echo "==> Stopping any running copy"
launchctl bootout "gui/$(id -u)/com.fighter.sentinel" 2>/dev/null || true
osascript -e 'quit app "Sentinel"' 2>/dev/null || true
sleep 2
pkill -f "Sentinel.app/Contents/MacOS/Sentinel" 2>/dev/null || true

echo "==> Installing to /Applications"
rm -rf /Applications/Sentinel.app
ditto "$APP" /Applications/Sentinel.app
xattr -dr com.apple.quarantine /Applications/Sentinel.app 2>/dev/null || true
# Apple silicon refuses to run modified binaries without a signature: ad-hoc sign the whole bundle.
codesign --force --deep --sign - /Applications/Sentinel.app

echo "==> First launch (registers the login agent)"
open /Applications/Sentinel.app

DMG="$(ls dist/*.dmg 2>/dev/null | head -1 || true)"
cat <<MSG

Sentinel is installed and running in the menu bar.
  - Starts automatically at every login (tray menu: "Start automatically at login" to turn off)
  - Relaunches itself if it crashes; re-checks the engine after sleep / screen unlock
  - Installer for other Macs: ${DMG:-dist/*.dmg}
Uninstall: bash scripts/uninstall_mac.sh
MSG
