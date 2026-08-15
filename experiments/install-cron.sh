#!/usr/bin/env bash
# Install (or print) the daily 08:15 cron entry. Idempotent: marker line
# prevents duplicates. Removing it: ./uninstall-cron.sh.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$HERE/daily-capture.sh"
MARKER="# supply-core-daily-capture"
LINE="15 8 * * * /bin/bash $SCRIPT >> $HERE/data/cron.log 2>&1 $MARKER"

chmod +x "$SCRIPT"
current="$(crontab -l 2>/dev/null || true)"
if printf '%s\n' "$current" | grep -Fq "$MARKER"; then
  echo "already installed:"
  printf '%s\n' "$current" | grep -F "$MARKER"
  exit 0
fi
{ printf '%s\n%s\n' "$current" "$LINE"; } | crontab -
echo "installed:"
echo "  $LINE"
