#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
MARKER="# supply-core-daily-capture"
current="$(crontab -l 2>/dev/null || true)"
if printf '%s\n' "$current" | grep -Fq "$MARKER"; then
  printf '%s\n' "$current" | grep -vF "$MARKER" | crontab -
  echo "removed"
else
  echo "not installed"
fi
