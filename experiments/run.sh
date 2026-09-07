#!/usr/bin/env bash
# Daily capture: run supply-core against every candidate, store timestamped JSON.
# The committed baseline is managed separately. Report: ./report.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="${SUPPLY_BIN:-$HERE/../target/release/supply-core}"
[ -x "$BIN" ] || BIN="$HERE/../target/debug/supply-core"
DATA="$HERE/data"
DAY="${1:-$(date +%Y-%m-%d)}"
DIR="$DATA/$DAY"
OSV_CACHE="$DATA/osv-cache"
mkdir -p "$DIR"
failed=0

while IFS=$'\t' read -r name root tracks; do
  case "$name" in ''|'#'*) continue;; esac
  [ -d "$root" ] || { echo "FAIL $name (missing: $root)"; failed=1; continue; }
  case "$tracks" in
    *npm*)
      out="$DIR/$name.npm.json"
      start=$(python3 -c 'import time; print(time.time())')
      if "$BIN" snapshot-npm "$root" --osv --osv-cache "$OSV_CACHE" > "$out" 2>"$DIR/$name.npm.err"; then
        if ! python3 - "$out" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
if not isinstance(doc.get("dependencies"), list) or doc.get("errors") != []:
    print(f"Incomplete npm snapshot: {doc.get('errors', 'missing errors field')}", file=sys.stderr)
    sys.exit(1)
PY
        then
          failed=1
          echo "FAIL $name npm snapshot is incomplete"
        else
          echo "OK   $name npm"
        fi
      else
        failed=1
        echo "FAIL $name snapshot-npm (see $name.npm.err)"
      fi
      end=$(python3 -c 'import time; print(time.time())')
      python3 -c "print(f'{$end-$start:.2f}s')" > "$DIR/$name.npm.time"
      ;;
  esac
  case "$tracks" in
    *actions*)
      out="$DIR/$name.actions.json"
      start=$(python3 -c 'import time; print(time.time())')
      # exit 2 = blocking findings, expected; capture anyway
      rc=0
      "$BIN" scan-actions "$root" --json > "$out" 2>"$DIR/$name.actions.err" || rc=$?
      if [ "$rc" -eq 0 ] || [ "$rc" -eq 2 ]; then
        echo "OK   $name actions"
      else
        failed=1
        echo "FAIL $name scan-actions (see $name.actions.err)"
      fi
      end=$(python3 -c 'import time; print(time.time())')
      python3 -c "print(f'{$end-$start:.2f}s')" > "$DIR/$name.actions.time"
      ;;
  esac
done < "$HERE/candidates.txt"

echo "captured $DAY -> $DIR"
exit "$failed"
