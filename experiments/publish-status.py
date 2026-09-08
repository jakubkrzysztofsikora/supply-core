#!/usr/bin/env python3
"""Convert one daily capture into the public quarantine snapshot."""
import json
import sys
from pathlib import Path


def fail(message):
    raise SystemExit(message)


if len(sys.argv) != 2:
    fail("usage: publish-status.py <daily-capture-directory>")

capture_dir = Path(sys.argv[1])
files = sorted(capture_dir.glob("*.npm.json"))
if not files:
    fail("no npm snapshots found")

captured_at = []
packages = set()
for path in files:
    try:
        report = json.loads(path.read_text())
        captured_at.append(report["captured_at"])
        dependencies = report["dependencies"]
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as error:
        fail(f"invalid npm snapshot {path}: {error}")
    if not isinstance(dependencies, list):
        fail(f"invalid dependencies in {path}")
    for dependency in dependencies:
        reasons = dependency.get("reasons", [])
        if not any("inside quarantine window" in reason for reason in reasons):
            continue
        try:
            package = (
                dependency["package"], dependency["resolved"],
                dependency["age_days"], dependency["status"],
            )
        except KeyError as error:
            fail(f"missing quarantine field in {path}: {error}")
        if not package[0] or not package[1] or package[2] < 0:
            fail(f"invalid quarantine package in {path}")
        packages.add(package)

snapshot = {
    "captured_at": max(captured_at),
    "packages": [
        {"name": name, "version": version, "age_days": age_days, "status": status}
        for name, version, age_days, status in sorted(packages)
    ],
}
print(json.dumps(snapshot, separators=(",", ":")))
