#!/usr/bin/env bash
# Renders docs/brand/banner.html to banner.png at 1000x380 (2x), same pipeline as heyatom-portfolio/og.
set -euo pipefail
cd "$(dirname "$0")"

CHROME="${CHROME:-$(ls -d ~/.cache/puppeteer/chrome-headless-shell/*/*/chrome-headless-shell 2>/dev/null | sort -V | tail -1)}"
[ -x "$CHROME" ] || { echo "chrome-headless-shell not found: npx @puppeteer/browsers install chrome-headless-shell, or set CHROME=" >&2; exit 1; }

"$CHROME" --allow-file-access-from-files --hide-scrollbars --window-size=1000,380 --force-device-scale-factor=2 --default-background-color=00000000 \
  --virtual-time-budget=8000 --screenshot="$PWD/banner.png" "file://$PWD/banner.html" >/dev/null 2>&1
magick banner.png -strip banner.png
echo banner.png
