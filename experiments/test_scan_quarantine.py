#!/usr/bin/env python3
"""Offline tests for scan-quarantine.py (no registry, no GuardDog)."""
import base64
import hashlib
import importlib.util
import json
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

    def test_duplicates_and_malformed_entries_are_skipped(self):
        documents = [
            snapshot([
                dependency("marked", "18.0.13", ["inside quarantine window"]),
                dependency("marked", "18.0.13", ["inside quarantine window"]),
                {"resolved": "1.0.0", "reasons": ["inside quarantine window"]},
                dependency("zod", None, ["inside quarantine window"]),
            ]),
            {"dependencies": "not-a-list"},
        ]
        self.assertEqual(
            scan_quarantine.quarantined_packages(documents),
            [{"package": "marked", "version": "18.0.13"}],
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
    def test_summarize_merges_rules_and_scores(self):
        findings = [
            {"score": 5, "rules": ["slopsquat-name"], "source": "static-heuristics"},
            {"score": 9, "rules": ["ai-prompt-injection"], "source": "static-heuristics"},
        ]
        self.assertEqual(
            scan_quarantine.summarize(findings),
            {"findings": 2, "score": 9,
             "rules": ["ai-prompt-injection", "slopsquat-name"],
             "sources": ["static-heuristics"]},
        )
        self.assertEqual(
            scan_quarantine.summarize([]),
            {"findings": 0, "score": 0, "rules": [], "sources": []},
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
    def test_record_is_block_level_and_tagged_by_engine(self):
        record = scan_quarantine.incomplete_record("evil", "1.0.0", "boom", guarddog=True)
        self.assertEqual(record["rules"], ["scan-incomplete", "guarddog"])
        self.assertEqual(record["score"], 8)
        self.assertEqual(record["package"], "evil")
        self.assertIn("boom", record["summary"])
        static = scan_quarantine.incomplete_record("evil", "1.0.0", "boom", guarddog=False)
        self.assertEqual(static["rules"], ["scan-incomplete", "static"])

    def test_append_and_clear_round_trip(self):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "findings.jsonl"
            scan_quarantine.append_record(
                path, scan_quarantine.incomplete_record("a", "1.0.0", "boom", guarddog=True)
            )
            scan_quarantine.append_record(
                path, scan_quarantine.incomplete_record("b", "2.0.0", "boom", guarddog=False)
            )
            scan_quarantine.append_record(path, {
                "ecosystem": "Npm", "package": "b", "version": "2.0.0",
                "source": "guarddog", "score": 9, "rules": ["threat-x"], "summary": "real",
            })
            # A static-only run must not clear a GuardDog-pending hold.
            self.assertEqual(
                scan_quarantine.clear_incomplete(path, "a", "1.0.0", includes_guarddog=False), 0
            )
            self.assertEqual(
                scan_quarantine.clear_incomplete(path, "a", "1.0.0", includes_guarddog=True), 1
            )
            self.assertEqual(
                scan_quarantine.clear_incomplete(path, "a", "1.0.0", includes_guarddog=True), 0
            )
            # Static-tagged records clear after any successful scan.
            self.assertEqual(
                scan_quarantine.clear_incomplete(path, "b", "2.0.0", includes_guarddog=False), 1
            )
            remaining = [line for line in path.read_text().splitlines() if line.strip()]
            self.assertEqual(len(remaining), 1)
            self.assertTrue(any('"threat-x"' in line for line in remaining))
            self.assertFalse(any('"scan-incomplete"' in line for line in remaining))

    def test_clear_on_missing_file_is_a_noop(self):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "missing.jsonl"
            self.assertEqual(
                scan_quarantine.clear_incomplete(path, "a", "1.0.0", includes_guarddog=False), 0
            )

    def test_incomplete_candidates_are_retried_and_merged(self):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "findings.jsonl"
            scan_quarantine.append_record(
                path, scan_quarantine.incomplete_record("a", "1.0.0", "boom", guarddog=True)
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
    def _fake_binary(self, directory):
        binary = Path(directory) / "fake-supply"
        binary.write_text(
            "#!/bin/sh\n"
            "if [ -n \"${GUARDDOG_BIN:-}\" ]; then\n"
            "  echo '[\"guarddog-env-set\"]'\n"
            "else\n"
            "  echo '[]'\n"
            "fi\n"
        )
        binary.chmod(0o755)
        return binary

    def test_static_only_mode_does_not_crash(self):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            binary = self._fake_binary(directory)
            findings = Path(directory) / "findings.jsonl"
            with mock.patch.dict("os.environ", clear=True):
                result = scan_quarantine.scan_package(
                    str(binary), Path("archive.tgz"), "pkg", "1.0.0", findings, guarddog=None
                )
            self.assertEqual(result, [])

    def test_guarddog_path_is_exported_to_the_scanner(self):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            binary = self._fake_binary(directory)
            findings = Path(directory) / "findings.jsonl"
            result = scan_quarantine.scan_package(
                str(binary), Path("archive.tgz"), "pkg", "1.0.0", findings,
                guarddog="/opt/guarddog",
            )
            self.assertEqual(result, ["guarddog-env-set"])


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

    def test_available_uses_path(self):
        with mock.patch.object(scan_quarantine.shutil, "which", return_value="/usr/local/bin/guarddog"):
            self.assertTrue(scan_quarantine.guarddog_available("guarddog"))
        with mock.patch.object(scan_quarantine.shutil, "which", return_value=None):
            self.assertFalse(scan_quarantine.guarddog_available("definitely-missing"))


if __name__ == "__main__":
    unittest.main()
