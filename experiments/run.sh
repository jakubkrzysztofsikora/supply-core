#!/usr/bin/env bash
# Daily capture: run supply-core against every candidate, store timestamped JSON.
# First run per candidate = baseline. Report: ./report.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="${SUPPLY_BIN:-$HERE/../target/release/supply-core}"
[ -x "$BIN" ] || BIN="$HERE/../target/debug/supply-core"
DATA="$HERE/data"
DAY="${1:-$(date +%Y-%m-%d)}"
DIR="$DATA/$DAY"
mkdir -p "$DIR"

while IFS=$'\t' read -r name root tracks; do
  case "$name" in ''|'#'*) continue;; esac
  [ -d "$root" ] || { echo "SKIP $name (missing: $root)"; continue; }
  case "$tracks" in
    *npm*)
      out="$DIR/$name.npm.json"
      start=$(python3 -c 'import time; print(time.time())')
      "$BIN" snapshot-npm "$root" > "$out" 2>"$DIR/$name.npm.err" \
        || echo "FAIL $name snapshot-npm (see $name.npm.err)"
      end=$(python3 -c 'import time; print(time.time())')
      python3 -c "print(f'{$end-$start:.2f}s')" > "$DIR/$name.npm.time"
      echo "OK   $name npm ($(cat "$DIR/$name.npm.time"))"
      ;;
  esac
  case "$tracks" in
    *actions*)
      out="$DIR/$name.actions.json"
      start=$(python3 -c 'import time; print(time.time())')
      # exit 2 = blocking findings, expected; capture anyway
      "$BIN" scan-actions "$root" --json > "$out" 2>"$DIR/$name.actions.err" \
        || [ $? -eq 2 ] || echo "FAIL $name scan-actions (see $name.actions.err)"
      end=$(python3 -c 'import time; print(time.time())')
      python3 -c "print(f'{$end-$start:.2f}s')" > "$DIR/$name.actions.time"
      echo "OK   $name actions ($(cat "$DIR/$name.actions.time"))"
      ;;
  esac
done < "$HERE/candidates.txt"

echo "captured $DAY -> $DIR"
