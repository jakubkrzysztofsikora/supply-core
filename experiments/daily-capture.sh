#!/usr/bin/env bash
# Daily capture wrapper. Pulls latest from origin (candidates.txt,
# run.sh, report.py, source code), rebuilds the binary, and runs the
# capture. The cron entry in install-cron.sh calls this.
#
# Cron runs under a stripped PATH (no ~/.cargo/bin), so we hard-code the
# rustup bin dir. Idempotent: a failed git pull is non-fatal, a failed
# cargo build skips run.sh but still logs and exits non-zero.
set -uo pipefail   # NOTE: no -e; each phase logs and continues.
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
BIN="$ROOT/target/release/supply-core"
LOG="$HERE/data/cron.log"
DAY="$(date +%Y-%m-%d)"
mkdir -p "$HERE/data" || exit 1

# Cron-friendly PATH: rustup proxies live in ~/.cargo/bin; keep the system
# defaults for git/python3.
export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"

cd "$ROOT" || exit 1
{
  echo "=== $(date -u +%FT%TZ) ==="
  echo "user=$(id -un) path=$PATH"
  echo "cargo: $(command -v cargo 2>/dev/null || echo MISSING)"
  echo "rustc: $(command -v rustc 2>/dev/null || echo MISSING)"

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
  if cargo build --release --locked --quiet; then
    echo "binary $BIN ($(stat -f%Sm "$BIN" 2>/dev/null || stat -c%y "$BIN"))"
  else
    echo "ERROR: cargo build failed; skipping run.sh"
    exit 1
  fi

  capture_rc=0
  SUPPLY_BIN="$BIN" "$HERE/run.sh" "$DAY" || capture_rc=$?
  if [ "$capture_rc" -ne 0 ]; then
    echo "ERROR: run.sh failed (exit $capture_rc)"
  fi

  # Field-test gate: exit non-zero on regressions vs the committed baseline.
  # The cron job captures both stdout and stderr to cron.log; the exit
  # status is what surfaces alerts via whatever pager is wired up.
  if "$HERE/check.sh" "$HERE/data/$DAY" 2>&1; then
    echo "check.sh: OK"
  else
    rc=$?
    echo "check.sh: REGRESSIONS detected (exit $rc)"
    exit $rc
  fi

  echo "exit $capture_rc"
  exit "$capture_rc"
} >> "$LOG" 2>&1
