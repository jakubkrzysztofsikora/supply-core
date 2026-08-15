#!/usr/bin/env bash
# Daily capture wrapper. Pulls latest from origin (candidates.txt,
# run.sh, report.py, source code), rebuilds the binary, and runs the
# capture. The cron entry in install-cron.sh calls this.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
BIN="$ROOT/target/release/supply-core"
LOG="$HERE/data/cron.log"

cd "$ROOT"
{
  echo "=== $(date -u +%FT%TZ) ==="

  # Track upstream so candidates.txt / run.sh / source edits land here.
  branch="$(git rev-parse --abbrev-ref HEAD)"
  if git fetch --quiet origin "$branch" 2>/dev/null; then
    if ! git pull --ff-only --quiet origin "$branch" 2>/dev/null; then
      echo "WARN: git pull --ff-only failed (local commits?); running on local HEAD"
    fi
  else
    echo "WARN: git fetch failed (offline?); running on local HEAD"
  fi
  rev="$(git rev-parse --short HEAD)"
  echo "repo rev $rev on $branch"

  # Incremental release build. ~1s when nothing changed, ~30s after src edits.
  cargo build --release --locked --quiet
  echo "binary $BIN ($(stat -f%Sm "$BIN" 2>/dev/null || stat -c%y "$BIN"))"

  SUPPLY_BIN="$BIN" "$HERE/run.sh"
  echo "exit $?"
} >> "$LOG" 2>&1
