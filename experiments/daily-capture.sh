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

# Cron-friendly PATH: rustup proxies live in ~/.cargo/bin; GuardDog lives in
# ~/.local/bin; keep the system defaults for git/python3.
export PATH="$HOME/.cargo/bin:$HOME/.local/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
. "$HERE/capture-lock.sh"
capture_lock "$HERE/data/.daily-capture.lock" || exit 1
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
export SUPPLY_LEDGER_PATH="${SUPPLY_LEDGER_PATH:-$HERE/data/ledger.sqlite}"

# This private file supplies SUPPLY_STATUS_URL, SUPPLY_STATUS_AUTH_TOKEN and
# optionally SUPPLY_SCAN_IMAGE. It stays outside the repository because cron
# does not inherit shell secrets; values are exported for remote-scan.sh.
PUBLISH_ENV="${SUPPLY_STATUS_PUBLISH_ENV:-$HOME/.config/supply-core/status-publisher.env}"
if [ -r "$PUBLISH_ENV" ]; then
  set -a
  . "$PUBLISH_ENV"
  set +a
fi

cd "$ROOT" || exit 1
{
  echo "=== $(date -u +%FT%TZ) ==="
  echo "user=$(id -un) path=$PATH"
  echo "cargo: $(command -v cargo 2>/dev/null || echo MISSING)"
  echo "rustc: $(command -v rustc 2>/dev/null || echo MISSING)"

  # Track upstream so candidates.txt / run.sh / source edits land here.
  branch="$(git rev-parse --abbrev-ref HEAD 9>&-)"
  if git fetch --quiet origin "$branch" 9>&- 2>/dev/null; then
    if ! git pull --ff-only --quiet origin "$branch" 9>&- 2>/dev/null; then
      echo "WARN: git pull --ff-only failed (local commits?); running on local HEAD"
    fi
  else
    echo "WARN: git fetch failed (offline?); running on local HEAD"
  fi
  rev="$(git rev-parse --short HEAD 9>&-)"
  echo "repo rev $rev on $branch"

  # Incremental release build. ~1s when nothing changed, ~30s after src edits.
  if cargo build --release --locked --quiet 9>&-; then
    echo "binary $BIN ($(stat -f%Sm "$BIN" 2>/dev/null || stat -c%y "$BIN"))"
  else
    echo "ERROR: cargo build failed; skipping run.sh"
    exit 1
  fi

  run_rc=0
  SUPPLY_BIN="$BIN" "$HERE/run.sh" "$DAY" || run_rc=$?
  capture_rc=$run_rc
  if [ "$run_rc" -ne 0 ]; then
    echo "ERROR: run.sh failed (exit $run_rc)"
  else
    scan_rc=0
    scan_locally=1
    if [ -n "${SUPPLY_SCAN_IMAGE:-}" ]; then
      scan_locally=0
      "$HERE/remote-scan.sh" "$HERE/data/$DAY" "$HERE/data/content-findings.jsonl" \
        "$SUPPLY_LEDGER_PATH" || scan_rc=$?
      if [ "$scan_rc" -eq 3 ]; then
        echo "WARN: remote Linux scan unavailable; scanning locally (external engines stay incomplete)"
        scan_rc=0
        scan_locally=1
      fi
    fi
    if [ "$scan_locally" -eq 1 ]; then
      scratch_args=()
      if [ -n "${SUPPLY_SCRATCH_DIR:-}" ]; then
        scratch_args+=(--scratch-dir "$SUPPLY_SCRATCH_DIR")
      fi
      SUPPLY_DAILY_CAPTURE_LOCK_FD=9 python3 "$HERE/scan-quarantine.py" "$HERE/data/$DAY" --bin "$BIN" \
        ${scratch_args[@]+"${scratch_args[@]}"} \
        --ledger-db "$SUPPLY_LEDGER_PATH" \
        --findings "$HERE/data/content-findings.jsonl" || scan_rc=$?
    fi
    if [ "$scan_rc" -ne 0 ]; then
      echo "ERROR: content scan failed (exit $scan_rc)"
      capture_rc=1
    fi

    if [ -n "${SUPPLY_STATUS_URL:-}" ] && [ -n "${SUPPLY_STATUS_AUTH_TOKEN:-}" ]; then
      snapshot="$HERE/data/$DAY/quarantine-status.json"
      if python3 "$HERE/publish-status.py" "$HERE/data/$DAY" > "$snapshot" \
        && curl --fail --silent --show-error --request PUT \
          --header "Authorization: Bearer $SUPPLY_STATUS_AUTH_TOKEN" \
          --header "Content-Type: application/json" \
          --data-binary "@$snapshot" \
          "${SUPPLY_STATUS_URL%/}/api/v1/status/quarantine"; then
        echo "published quarantine status"
      else
        echo "ERROR: failed to publish quarantine status"
        capture_rc=1
      fi
    else
      echo "WARN: quarantine status publisher is not configured"
    fi
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
