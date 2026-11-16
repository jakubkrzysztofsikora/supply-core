#!/usr/bin/env python3
"""Compare baseline (oldest) vs latest capture. Week-experiment feedback:
what works, what doesn't, efficiency. Run after `run.sh` on any later day."""
import json
import sys
import re
from pathlib import Path

HERE = Path(__file__).parent
DATA = HERE / "data"
sys.path.insert(0, str(HERE))
from capture_validation import validate_npm_capture


def load_days():
    days = sorted(d for d in DATA.iterdir()
                  if d.is_dir() and re.fullmatch(r"\d{4}-\d{2}-\d{2}", d.name))
    if len(days) < 2:
        print("need >= 2 capture days; run ./run.sh again later")
        sys.exit(1)
    return days[0], days[-1]


def load_capture(day_dir, name, track, required):
    path = day_dir / f"{name}.{track}.json"
    try:
        doc = json.loads(path.read_text())
        if not isinstance(doc, dict) or any(not isinstance(doc.get(key), list) for key in required):
            raise ValueError("missing or invalid " + "/".join(required) + " arrays")
        if track == "npm" and doc.get("errors") != []:
            raise ValueError(f"snapshot errors: {doc.get('errors', 'missing errors field')}")
        return doc
    except (OSError, ValueError, TypeError) as exc:
        return f"INCOMPLETE {name} {track} ({day_dir.name}): {exc}"


def npm_index(doc):
    entries = validate_npm_capture(doc)
    return {entry["package"]: entry for entry in entries}


def actions_index(doc):
    refs = doc["references"]
    if any(not isinstance(r, dict) or not all(k in r for k in ("file", "line", "raw", "pin_kind")) for r in refs):
        raise ValueError("invalid reference entry")
    return {(r["file"], r["line"], r["raw"]): r["pin_kind"] for r in refs}, len(doc["findings"])

def main():
    base, last = load_days()
    print(f"# supply-core field report: {base.name} -> {last.name}\n")
    candidates = [line.split("\t") for line in (HERE / "candidates.txt").read_text().splitlines()
                  if line and not line.startswith("#")]
    errors = []
    for name, _, tracks in candidates:
        if "npm" in tracks:
            bdoc = load_capture(base, name, "npm", ("dependencies",))
            ldoc = load_capture(last, name, "npm", ("dependencies",))
            for doc in (bdoc, ldoc):
                if isinstance(doc, str):
                    print(doc)
                    errors.append(doc)
            if not isinstance(bdoc, str) and not isinstance(ldoc, str):
                try:
                    b, l = npm_index(bdoc), npm_index(ldoc)
                    new_versions, flips, newly_held = [], [], []
                    for pkg, cur in l.items():
                        prev = b.get(pkg)
                        if prev is None:
                            continue
                        if prev.get("resolved") != cur.get("resolved"):
                            new_versions.append((pkg, prev.get("resolved"), cur.get("resolved"), cur.get("age_days")))
                        if prev.get("status") != cur.get("status"):
                            flips.append((pkg, prev.get("status"), cur.get("status")))
                        if cur.get("status") != "Allow" and prev.get("status") == "Allow":
                            newly_held.append(pkg)
                    bt = (base / f"{name}.npm.time").read_text().strip()
                    lt = (last / f"{name}.npm.time").read_text().strip()
                    print(f"## {name} (npm) - {len(l)} deps, runtime {bt} -> {lt}")
                    print(f"- upstream new versions: {len(new_versions)}")
                    for pkg, old, new, age in new_versions:
                        print(f"  - {pkg}: {old} -> {new} (age {age}d)")
                    print(f"- decision flips: {len(flips)}")
                    for pkg, old, new in flips:
                        print(f"  - {pkg}: {old} -> {new}")
                    print(f"- newly held (Allow -> Block/Fallback): {len(newly_held)}\\n")
                except (OSError, ValueError, KeyError, TypeError) as exc:
                    message = f"INCOMPLETE {name} npm report: {exc}"
                    print(message)
                    errors.append(message)
        if "actions" in tracks:
            bdoc = load_capture(base, name, "actions", ("references", "findings"))
            ldoc = load_capture(last, name, "actions", ("references", "findings"))
            for doc in (bdoc, ldoc):
                if isinstance(doc, str):
                    print(doc)
                    errors.append(doc)
            if not isinstance(bdoc, str) and not isinstance(ldoc, str):
                try:
                    (brefs, bblocks), (lrefs, lblocks) = actions_index(bdoc), actions_index(ldoc)
                    added, removed = set(lrefs) - set(brefs), set(brefs) - set(lrefs)
                    bt = (base / f"{name}.actions.time").read_text().strip()
                    lt = (last / f"{name}.actions.time").read_text().strip()
                    print(f"## {name} (actions) - {len(brefs)} -> {len(lrefs)} refs, blocks {bblocks} -> {lblocks}, runtime {bt} -> {lt}")
                    for file, line, raw in sorted(added):
                        print(f"  + {raw} ({file}:{line}) pin={lrefs[(file, line, raw)]}")
                    for file, line, raw in sorted(removed):
                        print(f"  - {raw} ({file}:{line})")
                except (OSError, ValueError, KeyError, TypeError) as exc:
                    message = f"INCOMPLETE {name} actions report: {exc}"
                    print(message)
                    errors.append(message)
    if errors:
        print(f"INCOMPLETE: {len(errors)} expected captures/reports invalid")
        return 1
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
