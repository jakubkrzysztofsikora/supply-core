#!/usr/bin/env bash
# Daily capture: run supply-core against every candidate, store timestamped JSON.
# The committed baseline is managed separately. Report: ./report.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="${SUPPLY_BIN:-$HERE/../target/release/supply-core}"
[ -x "$BIN" ] || BIN="$HERE/../target/debug/supply-core"
DATA="$HERE/data"
. "$HERE/capture-lock.sh"
capture_lock "$DATA/.daily-capture.lock" || exit 1
DAY="${1:-$(date +%Y-%m-%d)}"
DIR="$DATA/$DAY"
OSV_CACHE="$DATA/osv-cache"
POLICY="$HERE/policy.yml"
FINDINGS="$DATA/content-findings.jsonl"
LEDGER_DB="${SUPPLY_LEDGER_PATH:-$DATA/ledger.sqlite}"
mkdir -p "$DIR"
rm -f "$DIR"/*
failed=0
attempted=0

while IFS=$'\t' read -r name root tracks; do
  case "$name" in ''|'#'*) continue;; esac
  attempted=$((attempted + 1))
  [ -d "$root" ] || { echo "INCOMPLETE $name (missing candidate: $root)"; failed=1; continue; }
  case "$tracks" in
    *npm*)
      out="$DIR/$name.npm.json"
      extra=()
      if [ -f "$POLICY" ]; then extra+=(--policy "$POLICY"); fi
      if [ -f "$FINDINGS" ]; then extra+=(--findings "$FINDINGS"); fi
      start=$(python3 -c 'import time; print(time.time())')
      if "$BIN" snapshot-npm "$root" --ledger-db "$LEDGER_DB" --osv --osv-cache "$OSV_CACHE" ${extra[@]+"${extra[@]}"} > "$out" 2>"$DIR/$name.npm.err"; then
        if ! python3 - "$out" "$HERE" <<'PY'
import json, sys
sys.path.insert(0, sys.argv[2])
from capture_validation import validate_npm_capture
with open(sys.argv[1], encoding="utf-8") as report_file:
    doc = json.load(report_file)
dependencies = validate_npm_capture(doc)
print(f"CAPTURED npm packages={len(dependencies)} flagged={sum(d['status'] != 'Allow' for d in dependencies)}")
PY
        then
          failed=1
          echo "FAIL $name npm snapshot is incomplete"
        else
          :
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
        if ! python3 - "$out" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
if not isinstance(doc, dict) or not isinstance(doc.get("references"), list) or not isinstance(doc.get("findings"), list):
    print("Incomplete actions snapshot: missing or invalid references/findings arrays", file=sys.stderr)
    sys.exit(1)
print(f"CAPTURED actions references={len(doc['references'])} findings={len(doc['findings'])}")
PY
        then
          failed=1
          echo "INCOMPLETE $name actions snapshot"
        fi
      else
        failed=1
        echo "FAIL $name scan-actions (see $name.actions.err)"
      fi
      end=$(python3 -c 'import time; print(time.time())')
      python3 -c "print(f'{$end-$start:.2f}s')" > "$DIR/$name.actions.time"
      ;;
  esac
done < "$HERE/candidates.txt"

echo "captured $DAY -> $DIR ($attempted candidates)"
if [ "$attempted" -eq 0 ]; then
  echo "ERROR: no candidates found; nothing captured"
  exit 1
fi
exit "$failed"
