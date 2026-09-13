#!/usr/bin/env python3
"""Offline tests for publish-status.py (no network, no live server)."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parent / "publish-status.py"
spec = importlib.util.spec_from_file_location("publish_status", MODULE_PATH)
publish_status = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publish_status)


def dependency(name, version, reasons=None, warnings=None, age=0, status="Block"):
    return {
        "package": name,
        "resolved": version,
        "age_days": age,
        "status": status,
        "reasons": reasons or [],
        "warnings": warnings or [],
    }


class QuarantinedTest(unittest.TestCase):
    def test_window_reasons_are_selected_and_deduplicated(self):
        dependencies = [
            dependency("marked", "18.0.13", ["package version is inside quarantine window"], age=0),
            dependency("marked", "18.0.13", ["inside quarantine window"], age=0),
            dependency("lodash", "4.17.21", ["high vulnerability GHSA-1 from OSV"]),
        ]
        self.assertEqual(
            publish_status.quarantined_packages(dependencies),
            [{"name": "marked", "version": "18.0.13", "age_days": 0, "status": "Block"}],
        )

    def test_missing_fields_fail_closed(self):
        with self.assertRaises(SystemExit):
            publish_status.quarantined_packages(
                [{"package": "x", "reasons": ["inside quarantine window"]}]
            )


class ConfirmedTest(unittest.TestCase):
    def test_advisories_are_parsed_and_ranked(self):
        dependencies = [
            dependency("a", "1.0.0", ["medium vulnerability GHSA-low from OSV"]),
            dependency("b", "2.0.0", ["critical vulnerability CVE-2026-1 from OSV"]),
            dependency("c", "3.0.0", ["package version is inside quarantine window"]),
        ]
        rows = publish_status.confirmed_findings(dependencies)
        self.assertEqual(
            rows,
            [
                {"name": "b", "version": "2.0.0", "advisory": "CVE-2026-1", "severity": "critical"},
                {"name": "a", "version": "1.0.0", "advisory": "GHSA-low", "severity": "medium"},
            ],
        )

    def test_duplicate_advisories_collapse(self):
        reason = ["high vulnerability GHSA-x from OSV"]
        dependencies = [dependency("a", "1.0.0", reason), dependency("a", "1.0.0", list(reason))]
        self.assertEqual(len(publish_status.confirmed_findings(dependencies)), 1)


class SuspectedTest(unittest.TestCase):
    def test_scan_report_is_preferred_and_ranked(self):
        dependencies = [
            dependency("zod", "4.6.4", warnings=["content scan review (score 1): x [obfuscation]"]),
            dependency("evil", "1.0.0", ["content scan: beacon [ai-install-script]"]),
        ]
        scan_report = {
            "scanned": [
                {"package": "zod", "version": "4.6.4", "findings": 1, "score": 1,
                 "rules": ["obfuscation", "provenance-attested"]},
                {"package": "clean", "version": "9.9.9", "findings": 0, "score": 0, "rules": []},
                {"package": "evil", "version": "1.0.0", "findings": 1, "score": 9,
                 "rules": ["ai-install-script", "extra", "r3", "r4", "r5", "r6", "r7", "r8", "r9"]},
            ]
        }
        rows = publish_status.suspected_findings(dependencies, scan_report)
        self.assertEqual(rows[0]["name"], "evil")
        self.assertEqual(rows[0]["score"], 9)
        self.assertEqual(len(rows[0]["rules"]), publish_status.MAX_RULES)
        self.assertEqual(rows[1], {"name": "zod", "version": "4.6.4", "score": 1,
                                   "rules": ["obfuscation", "provenance-attested"]})

    def test_warnings_are_fallback_when_no_scan_report(self):
        dependencies = [
            dependency("zod", "4.6.4", warnings=["content scan review (score 4): x [obfuscation]"]),
            dependency("odd", "1.0.0", ["content scan: something [rule-a]"]),
        ]
        rows = publish_status.suspected_findings(dependencies, None)
        self.assertEqual([row["name"] for row in rows], ["zod", "odd"])
        self.assertEqual(rows[0]["score"], 4)
        self.assertEqual(rows[1]["score"], 0)

    def test_malformed_scan_report_is_ignored(self):
        dependencies = [dependency("odd", "1.0.0", warnings=["content scan review (score 4): x [r]"])]
        rows = publish_status.suspected_findings(dependencies, {"scanned": "nope"})
        self.assertEqual(len(rows), 1)


class SnapshotTest(unittest.TestCase):
    def test_snapshot_aggregates_a_capture_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory)
            (capture / "evil.npm.json").write_text(json.dumps({
                "captured_at": "2026-09-13T06:45:00Z",
                "dependencies": [
                    dependency("evil", "1.0.0", ["content scan: beacon [ai-install-script]"],
                               age=0, status="Block"),
                    dependency("marked", "18.0.13", ["package version is inside quarantine window"],
                               age=0, status="Block"),
                ],
            }))
            (capture / "other.npm.json").write_text(json.dumps({
                "captured_at": "2026-09-13T06:46:00Z",
                "dependencies": [
                    dependency("lib", "2.0.0", ["high vulnerability GHSA-x from OSV"]),
                ],
            }))
            (capture / "content-scan.json").write_text(json.dumps({
                "scanned": [
                    {"package": "evil", "version": "1.0.0", "findings": 1, "score": 9,
                     "rules": ["ai-install-script"]},
                ]
            }))
            snapshot = publish_status.build_snapshot(capture)
            self.assertEqual(snapshot["captured_at"], "2026-09-13T06:46:00Z")
            self.assertEqual(snapshot["packages"][0]["name"], "marked")
            self.assertEqual(snapshot["confirmed"][0]["advisory"], "GHSA-x")
            self.assertEqual(snapshot["suspected"][0]["name"], "evil")
            self.assertEqual(snapshot["suspected"][0]["score"], 9)

    def test_missing_snapshots_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(SystemExit):
                publish_status.build_snapshot(Path(directory))


if __name__ == "__main__":
    unittest.main()
