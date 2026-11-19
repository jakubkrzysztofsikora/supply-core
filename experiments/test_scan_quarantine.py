#!/usr/bin/env python3
"""Offline tests for scan-quarantine.py (no registry, no GuardDog)."""
import base64
import hashlib
import importlib.util
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

MODULE_PATH = Path(__file__).resolve().parent / "scan-quarantine.py"
spec = importlib.util.spec_from_file_location("scan_quarantine", MODULE_PATH)
scan_quarantine = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan_quarantine)


def snapshot(dependencies):
    return {"captured_at": "2026-09-13T06:53:35Z", "dependencies": dependencies}


def dependency(name, version, reasons):
    return {"package": name, "resolved": version, "status": "Block", "reasons": reasons}


class QuarantinedPackagesTest(unittest.TestCase):
    def test_only_window_reasons_are_selected(self):
        documents = [
            snapshot([
                dependency("marked", "18.0.13", ["package version is inside quarantine window"]),
                dependency("lodash", "4.17.21", ["known advisory GHSA-x"]),
                dependency("handlebars", "4.7.6", ["critical vulnerability GHSA-x from OSV"]),
            ]),
            snapshot([
                dependency("zod", "4.6.4", ["package version is inside quarantine window"]),
            ]),
        ]
        self.assertEqual(
            scan_quarantine.quarantined_packages(documents),
            [
                {"package": "marked", "version": "18.0.13"},
                {"package": "zod", "version": "4.6.4"},
            ],
        )

    def test_advisory_blocked_packages_are_selected_separately(self):
        documents = [
            snapshot([
                dependency("handlebars", "4.7.6", ["critical vulnerability GHSA-x from OSV"]),
                dependency("zod", "3.25.76", ["high vulnerability GHSA-y from OSV"]),
                dependency("safe", "1.0.0", ["medium vulnerability GHSA-z from OSV"]),
                dependency("plain", "1.0.0", ["package version is inside quarantine window"]),
            ])
        ]
        self.assertEqual(
            scan_quarantine.advisory_blocked_packages(documents),
            [
                {"package": "handlebars", "version": "4.7.6"},
                {"package": "zod", "version": "3.25.76"},
            ],
        )

    def test_scan_plan_gives_advisory_versions_precedence(self):
        window = [{"package": "a", "version": "1.0.0"}]
        advisory = [
            {"package": "handlebars", "version": "4.7.6"},
            {"package": "a", "version": "1.0.0"},
        ]
        pending = [{"package": "b", "version": "2.0.0"}]
        self.assertEqual(
            scan_quarantine.scan_plan(window, advisory, pending),
            [
                {"package": "b", "version": "2.0.0", "enforce": True},
                {"package": "handlebars", "version": "4.7.6", "enforce": False},
                {"package": "a", "version": "1.0.0", "enforce": False},
            ],
        )
        self.assertEqual(
            [item["package"] for item in scan_quarantine.scan_plan(window, [], pending)],
            ["a", "b"],
        )


class NamingTest(unittest.TestCase):
    def test_scoped_names_are_flattened_without_collisions(self):
        scoped = scan_quarantine.safe_file_name("@scope/pkg", "1.2.3")
        self.assertTrue(scoped.startswith("scope_pkg-"), scoped)
        self.assertTrue(scoped.endswith("-1.2.3.tgz"), scoped)
        self.assertNotEqual(scoped, scan_quarantine.safe_file_name("scope_pkg", "1.2.3"))
        plain = scan_quarantine.safe_file_name("pkg", "1.2.3")
        self.assertTrue(plain.startswith("pkg-"), plain)
        self.assertTrue(plain.endswith("-1.2.3.tgz"), plain)

    def test_version_url_encodes_scopes(self):
        self.assertEqual(
            scan_quarantine.version_url("@scope/pkg", "1.2.3"),
            "https://registry.npmjs.org/@scope%2Fpkg/1.2.3",
        )
        self.assertEqual(
            scan_quarantine.version_url("pkg", "1.2.3"),
            "https://registry.npmjs.org/pkg/1.2.3",
        )


class VersionDocumentTest(unittest.TestCase):
    def test_valid_document(self):
        tarball, integrity = scan_quarantine.parse_version_document(
            {"dist": {"tarball": "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz",
                      "integrity": "sha512-abc"}},
            "pkg", "1.0.0",
        )
        self.assertEqual(tarball, "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz")
        self.assertEqual(integrity, "sha512-abc")

    def test_foreign_host_and_integrity_fail_closed(self):
        for dist in (
            {"tarball": "https://evil.test/pkg.tgz", "integrity": "sha512-abc"},
            {"tarball": "https://registry.npmjs.org/pkg.tgz", "integrity": "sha1-abc"},
            {"tarball": "https://registry.npmjs.org/pkg.tgz"},
        ):
            with self.assertRaises(ValueError):
                scan_quarantine.parse_version_document({"dist": dist}, "pkg", "1.0.0")
        with self.assertRaises(ValueError):
            scan_quarantine.parse_version_document({}, "pkg", "1.0.0")


class IntegrityTest(unittest.TestCase):
    def test_matching_bytes_pass_and_tampered_bytes_fail(self):
        data = b"tarball bytes"
        digest = base64.b64encode(hashlib.sha512(data).digest()).decode()
        scan_quarantine.verify_integrity(data, f"sha512-{digest}")
        with self.assertRaises(ValueError):
            scan_quarantine.verify_integrity(data + b"x", f"sha512-{digest}")


class ArchiveCacheTest(unittest.TestCase):
    @staticmethod
    def _integrity(data):
        digest = base64.b64encode(hashlib.sha512(data).digest()).decode()
        return f"sha512-{digest}"

    def test_corrupted_cache_entry_is_replaced(self):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "pkg.tgz"
            archive.write_bytes(b"corrupt")
            fresh = b"fresh bytes"
            with mock.patch.object(scan_quarantine, "fetch", return_value=fresh) as fetch_mock:
                scan_quarantine.ensure_archive(
                    archive, "https://registry.npmjs.org/x.tgz", self._integrity(fresh)
                )
                fetch_mock.assert_called_once()
            self.assertEqual(archive.read_bytes(), fresh)

    def test_valid_cache_entry_is_kept(self):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "pkg.tgz"
            payload = b"payload"
            archive.write_bytes(payload)
            with mock.patch.object(scan_quarantine, "fetch") as fetch_mock:
                result = scan_quarantine.ensure_archive(
                    archive, "https://registry.npmjs.org/x.tgz", self._integrity(payload)
                )
                fetch_mock.assert_not_called()
            self.assertEqual(result, payload)

    def test_tampered_download_is_rejected_and_not_cached(self):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "pkg.tgz"
            with mock.patch.object(scan_quarantine, "fetch", return_value=b"evil"):
                with self.assertRaises(ValueError):
                    scan_quarantine.ensure_archive(
                        archive, "https://registry.npmjs.org/x.tgz", self._integrity(b"good")
                    )
            self.assertFalse(archive.exists())


class WriteSummaryTest(unittest.TestCase):
    def test_full_scan_report_is_preserved_for_publishing(self):
        import tempfile

        report = {"scanned": [{"package": f"p{index}"} for index in range(250)], "errors": []}
        with tempfile.TemporaryDirectory() as directory:
            path = scan_quarantine.write_summary(report, Path(directory))
            saved = json.loads(path.read_text())
        self.assertEqual(len(saved["scanned"]), 250)


class SummaryTest(unittest.TestCase):
    def test_summarize_uses_artifact_report_scores_and_decision(self):
        report = {
            "decision": "block",
            "coverage": "partial",
            "engines": [
                {
                    "source": "static-heuristics",
                    "findings": [
                        {"policy_score": "5", "rule": "slopsquat-name"},
                        {"policy_score": "9", "rule": "ai-prompt-injection"},
                    ],
                },
                {"source": "guarddog", "findings": [], "reason": "scanner_memory_limit_unavailable"},
                {"source": "ossgadget", "findings": [], "reason": None},
            ],
        }
        self.assertEqual(
            scan_quarantine.summarize(report),
            {
                "decision": "block",
                "coverage": "partial",
                "findings": 2,
                "score": 9,
                "rules": ["ai-prompt-injection", "slopsquat-name"],
                "sources": ["static-heuristics"],
                "reasons": ["guarddog:scanner_memory_limit_unavailable"],
            },
        )
        self.assertEqual(
            scan_quarantine.summarize(
                {"decision": "pass", "coverage": "complete", "engines": []}
            ),
            {
                "decision": "pass",
                "coverage": "complete",
                "findings": 0,
                "score": 0,
                "rules": [],
                "sources": [],
                "reasons": [],
            },
        )


class LimitTest(unittest.TestCase):
    def test_zero_means_all_and_positive_truncates(self):
        packages = [{"package": name} for name in ("a", "b", "c")]
        self.assertEqual(scan_quarantine.limited(packages, 0), packages)
        self.assertEqual(scan_quarantine.limited(packages, -5), packages)
        self.assertEqual(scan_quarantine.limited(packages, 2), packages[:2])


class CacheTest(unittest.TestCase):
    def test_prune_cache_removes_only_stale_tarballs(self):
        import os
        import tempfile
        import time

        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            fresh = cache / "fresh-1.0.0.tgz"
            fresh.write_bytes(b"x")
            stale = cache / "stale-1.0.0.tgz"
            stale.write_bytes(b"x")
            old = time.time() - 31 * 86400
            os.utime(stale, (old, old))
            self.assertEqual(scan_quarantine.prune_cache(cache), 1)
            self.assertTrue(fresh.exists())
            self.assertFalse(stale.exists())


class IncompleteRecordTest(unittest.TestCase):
    def test_record_is_block_level_without_a_score(self):
        record = scan_quarantine.incomplete_record("evil", "1.0.0", "boom")
        self.assertEqual(record["rules"], ["scan-incomplete"])
        self.assertTrue(record["scan_incomplete"])
        self.assertNotIn("score", record)
        self.assertEqual(record["package"], "evil")
        self.assertIn("boom", record["summary"])

    def test_append_and_clear_preserves_confirmed_findings(self):
        import tempfile

        artifact_a, artifact_b = "a" * 64, "b" * 64
        policy = "c" * 64
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "findings.jsonl"
            scan_quarantine.append_record(
                path,
                scan_quarantine.incomplete_record(
                    "a", "1.0.0", "boom", artifact_a, policy
                ),
            )
            scan_quarantine.append_record(
                path,
                scan_quarantine.incomplete_record(
                    "b", "2.0.0", "boom", artifact_b, policy
                ),
            )
            scan_quarantine.append_record(path, {
                "ecosystem": "Npm", "package": "b", "version": "2.0.0",
                "source": "guarddog", "score": 9, "rules": ["threat-x"], "summary": "real",
            })
            self.assertEqual(scan_quarantine.clear_incomplete(path, "a", "1.0.0"), 1)
            self.assertEqual(scan_quarantine.clear_incomplete(path, "a", "1.0.0"), 0)
            self.assertEqual(scan_quarantine.clear_incomplete(path, "b", "2.0.0"), 1)
            remaining = [line for line in path.read_text().splitlines() if line.strip()]
            self.assertEqual(len(remaining), 1)
            self.assertTrue(any('"threat-x"' in line for line in remaining))
            self.assertFalse(any('"scan-incomplete"' in line for line in remaining))

    def test_clear_removes_digestless_holds_from_fetch_failures(self):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "findings.jsonl"
            for _ in range(3):
                scan_quarantine.append_record(
                    path, scan_quarantine.incomplete_record("sql.js", "1.15.0", "scan_failed")
                )
            scan_quarantine.append_record(
                path,
                scan_quarantine.incomplete_record("sql.js", "1.15.0", "boom", "a" * 64, "b" * 64),
            )
            scan_quarantine.append_record(path, {
                "ecosystem": "Npm", "package": "sql.js", "version": "1.15.0",
                "source": "guarddog", "score": 9, "rules": ["threat-x"], "summary": "real",
            })
            scan_quarantine.append_record(
                path, scan_quarantine.incomplete_record("sql.js", "9.9.9", "boom", "c" * 64, "d" * 64)
            )

            self.assertEqual(
                scan_quarantine.clear_incomplete(path, "sql.js", "1.15.0"), 4
            )
            remaining = [json.loads(line) for line in path.read_text().splitlines()]
        self.assertEqual(
            [(r["package"], r["version"]) for r in remaining],
            [("sql.js", "1.15.0"), ("sql.js", "9.9.9")],
        )
        self.assertEqual(remaining[0]["rules"], ["threat-x"])

    def test_clear_on_missing_file_is_a_noop(self):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "missing.jsonl"
            self.assertEqual(
                scan_quarantine.clear_incomplete(path, "a", "1.0.0"), 0
            )

    def test_incomplete_candidates_are_retried_and_merged(self):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "findings.jsonl"
            scan_quarantine.append_record(
                path, scan_quarantine.incomplete_record("a", "1.0.0", "boom")
            )
            scan_quarantine.append_record(path, {
                "ecosystem": "Npm", "package": "b", "version": "2.0.0",
                "source": "guarddog", "score": 9, "rules": ["threat-x"], "summary": "real",
            })
            pending = scan_quarantine.incomplete_candidates(path)
            self.assertEqual(pending, [{"package": "a", "version": "1.0.0"}])
            merged = scan_quarantine.merge_candidates(
                [{"package": "a", "version": "1.0.0"}, {"package": "c", "version": "3.0.0"}],
                pending,
            )
            self.assertEqual(
                merged,
                [{"package": "a", "version": "1.0.0"}, {"package": "c", "version": "3.0.0"}],
            )
        self.assertEqual(
            scan_quarantine.incomplete_candidates(Path(directory) / "gone.jsonl"), []
        )


class ScanPackageTest(unittest.TestCase):
    def _fake_binary(self, directory, decision, coverage, returncode):
        binary = Path(directory) / "fake-supply"
        report = json.dumps({
            "artifact_sha256": "abc",
            "policy_sha256": "def",
            "coverage": coverage,
            "decision": decision,
            "engines": [],
            "reason": None,
        })
        binary.write_text(
            "#!/bin/sh\n"
            "case \" $* \" in\n"
            f"  *\" --json \"*) printf '%s\\n' '{report}'; exit {returncode} ;;\n"
            "  *) printf '[]\\n'; exit 0 ;;\n"
            "esac\n"
        )
        binary.chmod(0o755)
        return binary

    def test_block_exit_returns_report_instead_of_execution_error(self):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            binary = self._fake_binary(directory, "block", "partial", 2)
            result = scan_quarantine.scan_package(
                str(binary), Path("archive.tgz"), "pkg", "1.0.0",
                Path(directory) / "findings.jsonl", scratch_dir=Path(directory),
            )
        self.assertEqual(result["decision"], "block")
        self.assertEqual(result["coverage"], "partial")

    def test_incomplete_exit_preserves_artifact_report(self):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            binary = self._fake_binary(directory, "incomplete", "partial", 3)
            result = scan_quarantine.scan_package(
                str(binary), Path("archive.tgz"), "pkg", "1.0.0",
                Path(directory) / "findings.jsonl", scratch_dir=Path(directory),
            )
        self.assertEqual(result["decision"], "incomplete")

    def test_unknown_exit_remains_an_execution_error(self):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            binary = self._fake_binary(directory, "pass", "complete", 1)
            with self.assertRaises(RuntimeError):
                scan_quarantine.scan_package(
                    str(binary), Path("archive.tgz"), "pkg", "1.0.0",
                    Path(directory) / "findings.jsonl", scratch_dir=Path(directory),
                )

    def test_durable_ledger_path_reaches_cli(self):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "ledger.sqlite"
            binary = self._fake_binary(directory, "pass", "complete", 0)
            result = scan_quarantine.scan_package(
                str(binary), Path("archive.tgz"), "pkg", "1.0.0",
                Path(directory) / "findings.jsonl", ledger_db=ledger,
                scratch_dir=Path(directory),
            )
        self.assertEqual(result["decision"], "pass")

    def test_verification_scan_omits_findings_output(self):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            recorder = Path(directory) / "argv.txt"
            binary = Path(directory) / "fake-supply"
            binary.write_text(
                "#!/bin/sh\n"
                f'printf "%s\\n" "$*" >> "{recorder}"\n'
                "printf '{\"decision\":\"pass\",\"coverage\":\"complete\",\"engines\":[]}\\n'\n"
            )
            binary.chmod(0o755)
            scan_quarantine.scan_package(
                str(binary), Path("archive.tgz"), "pkg", "1.0.0", None,
                scratch_dir=Path(directory),
            )
            argv = recorder.read_text()
        self.assertNotIn("--findings-out", argv)
        self.assertIn("--scratch-dir", argv)

class MainFlowTest(unittest.TestCase):
    """End-to-end candidate handling: enforcement only for quarantine holds."""

    def _run_main(self, directory, outcome):
        day = Path(directory) / "2026-11-19"
        day.mkdir()
        (day / "sikoras-chat.npm.json").write_text(json.dumps(snapshot([
            dependency("windowed", "1.0.0", ["package version is inside quarantine window"]),
            dependency("handlebars", "4.7.6", ["critical vulnerability GHSA-x from OSV"]),
        ])))
        findings = Path(directory) / "content-findings.jsonl"
        calls = []

        def fake_scan(binary, archive, name, version, findings_path, **kwargs):
            calls.append((name, version, findings_path, kwargs.get("scratch_dir")))
            decision, coverage, reason = outcome(name)
            report = {
                "decision": decision,
                "coverage": coverage,
                "engines": [],
                "reason": reason,
                "artifact_sha256": "a" * 64,
                "policy_sha256": "b" * 64,
            }
            return report

        with mock.patch.object(scan_quarantine, "fetch_json", return_value={
            "dist": {"tarball": "https://registry.npmjs.org/x.tgz", "integrity": "sha512-AAA"},
        }), mock.patch.object(scan_quarantine, "ensure_archive", return_value=b""), \
             mock.patch.object(scan_quarantine, "scan_package", side_effect=fake_scan), \
             mock.patch.object(sys, "argv", [
                 "scan-quarantine.py", str(day),
                 "--bin", sys.executable,
                 "--cache", str(Path(directory) / "cache"),
                 "--findings", str(findings),
                 "--ledger-db", str(Path(directory) / "ledger.sqlite"),
                 "--scratch-dir", str(Path(directory) / "scratch"),
             ]):
            rc = scan_quarantine.main()
        return rc, calls, findings, json.loads((day / "content-scan.json").read_text())

    def test_advisory_candidates_are_scanned_without_findings_output(self):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            rc, calls, findings, report = self._run_main(
                directory, lambda name: ("pass", "complete", None),
            )
            self.assertEqual(
                [(name, version, path) for name, version, path, _ in calls],
                [
                    ("windowed", "1.0.0", findings),
                    ("handlebars", "4.7.6", None),
                ],
            )
            self.assertTrue(all(scratch is not None for *_, scratch in calls))
            self.assertFalse(findings.exists())
            self.assertEqual(rc, 0)
            self.assertEqual(report["candidates"], 2)
            self.assertEqual(len(report["scanned"]), 2)
            self.assertEqual(report["errors"], [])

    def test_incomplete_advisory_scan_never_holds_but_fails_the_run(self):
        import tempfile

        def outcome(name):
            if name == "handlebars":
                return ("incomplete", "partial", "scanner_reported_errors")
            return ("pass", "complete", None)

        with tempfile.TemporaryDirectory() as directory:
            rc, _calls, findings, report = self._run_main(directory, outcome)
            self.assertFalse(findings.exists())
            self.assertEqual(
                [(e["package"], e["error"]) for e in report["verification_errors"]],
                [("handlebars", "scanner_reported_errors")],
            )
            self.assertEqual(report["errors"], [])
            self.assertEqual(rc, 1)
            self.assertEqual(
                [row["decision"] for row in report["scanned"]], ["pass", "incomplete"]
            )

    def test_incomplete_quarantine_scan_still_holds(self):
        import tempfile

        def outcome(name):
            if name == "windowed":
                return ("incomplete", "partial", "coverage_unverified")
            return ("pass", "complete", None)

        with tempfile.TemporaryDirectory() as directory:
            rc, _calls, findings, report = self._run_main(directory, outcome)
            records = [json.loads(line) for line in findings.read_text().splitlines()]
            self.assertEqual(rc, 1)
            self.assertEqual([(r["package"], r["version"]) for r in records], [("windowed", "1.0.0")])
            self.assertEqual([e["package"] for e in report["errors"]], ["windowed"])
            self.assertEqual(report["verification_errors"], [])
class GuarddogBinaryTest(unittest.TestCase):
    def test_explicit_and_environment_win(self):
        self.assertEqual(scan_quarantine.guarddog_binary("/opt/guarddog"), "/opt/guarddog")
        with mock.patch.dict("os.environ", {"GUARDDOG_BIN": "/env/guarddog"}, clear=False):
            self.assertEqual(scan_quarantine.guarddog_binary(None), "/env/guarddog")

    def test_path_lookup_is_used_when_not_local(self):
        with mock.patch("pathlib.Path.home", return_value=Path("/nonexistent-home")), \
             mock.patch.object(scan_quarantine.shutil, "which", return_value="/usr/local/bin/guarddog"):
            self.assertEqual(
                scan_quarantine.guarddog_binary(None), "/usr/local/bin/guarddog"
            )
        with mock.patch("pathlib.Path.home", return_value=Path("/nonexistent-home")), \
             mock.patch.object(scan_quarantine.shutil, "which", return_value=None):
            self.assertEqual(scan_quarantine.guarddog_binary(None), "guarddog")



if __name__ == "__main__":
    unittest.main()
