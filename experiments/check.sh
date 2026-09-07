#!/usr/bin/env bash
# Field-test gate. Compares today's capture against the committed
# baseline and exits non-zero on regressions so the cron pipeline
# surfaces them instead of silently overwriting.
#
# Regressions are:
#   - any npm dep that flips Allow -> Block / Fallback across the diff
#   - any newly-added unpinned Action reference (TagOrBranch, Docker, Unknown)
# New Allow -> Allow flips and newly-removed refs are not regressions.
#
# Usage:
#   ./check.sh                # diff today's capture vs baseline.json
#   ./check.sh <day-dir>      # diff <day-dir> vs baseline.json
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
DATA="$HERE/data"
BASELINE="$DATA/baseline.json"
LATEST="${1:-$DATA/$(date +%Y-%m-%d)}"

if [ ! -d "$LATEST" ]; then
  echo "no capture day found under $DATA" >&2
  exit 2
fi
if [ ! -f "$BASELINE" ]; then
  echo "missing baseline: $BASELINE" >&2
  exit 2
fi

python3 - "$BASELINE" "$LATEST" "$HERE/candidates.txt" <<'PY'
import json, sys
from collections import Counter
from pathlib import Path

baseline_path, latest_path, cand_path = sys.argv[1], sys.argv[2], sys.argv[3]
baseline = json.loads(Path(baseline_path).read_text())
latest_dir = Path(latest_path)

candidates = [l.split("\t") for l in Path(cand_path).read_text().splitlines()
              if l and not l.startswith("#")]

regressions = []
errors = []

def capture(name, track, field):
    path = latest_dir / f"{name}.{track}.json"
    try:
        doc = json.loads(path.read_text())
        if not isinstance(doc, dict) or not isinstance(doc.get(field), list):
            raise ValueError(f"missing or invalid {field}")
        if track == "npm" and doc.get("errors") != []:
            raise ValueError(f"snapshot errors: {doc.get('errors', 'missing errors field')}")
        return doc
    except (OSError, ValueError) as exc:
        errors.append(f"{name} {track}: {exc}")
        return None

for name, _, tracks in candidates:
    if "npm" in tracks:
        doc = capture(name, "npm", "dependencies")
        if doc is None:
            doc = {"dependencies": []}
        cur = {d["package"]: d for d in doc.get("dependencies", [])}
        prev = baseline.get("npm", {}).get(name, {})
        new_held = []
        for pkg, c in cur.items():
            p = prev.get(pkg)
            if p is None:
                continue
            if c["status"] != "Allow" and p["status"] == "Allow":
                new_held.append((pkg, c["resolved"], p["status"], c["status"], c.get("reasons", [])))
        if new_held:
            regressions.append(("npm", name, new_held))
    if "actions" in tracks:
        doc = capture(name, "actions", "references")
        if doc is None:
            continue
        # Count occurrences by (file, raw): line shifts are harmless,
        # but adding another unpinned occurrence is still a regression.
        cur_refs = doc["references"]
        prev_refs_raw = baseline.get("actions", {}).get(name, {})
        prev_counts = Counter()
        for kstr in prev_refs_raw.keys():
            parts = kstr.split("::", 2)
            if len(parts) == 3:
                fl, _ln, raw = parts
                prev_counts[(fl, raw)] += 1
        new_unpinned = []
        for r in cur_refs:
            fl, raw = r["file"], r["raw"]
            if prev_counts[(fl, raw)]:
                prev_counts[(fl, raw)] -= 1
                continue
            if r["pin_kind"] not in ("FullSha", "Local"):
                new_unpinned.append((fl, r["line"], raw, r["pin_kind"]))
        if new_unpinned:
            regressions.append(("actions", name, new_unpinned))

if errors:
    print(f"INCOMPLETE capture ({latest_dir.name}):", file=sys.stderr)
    for error in errors:
        print(f"  {error}", file=sys.stderr)
    sys.exit(2)

if not regressions:
    print(f"OK: no regressions vs baseline ({latest_dir.name})")
    sys.exit(0)

print(f"REGRESSIONS vs baseline ({baseline.get('captured_at','?')} -> {latest_dir.name}):")
for kind, name, items in regressions:
    print(f"  [{kind}] {name}")
    for item in items:
        if kind == "npm":
            pkg, ver, prev, cur, reasons = item
            reason_str = "; ".join(reasons) if reasons else ""
            print(f"    + {pkg}@{ver}  {prev} -> {cur}  ({reason_str})")
        else:
            fl, ln, raw, pin = item
            print(f"    + {raw} ({fl}:{ln}) pin={pin}")
sys.exit(1)
PY
