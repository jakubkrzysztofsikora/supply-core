import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('capture_report', Path(__file__).with_name('report.py'))
report = importlib.util.module_from_spec(spec)
spec.loader.exec_module(report)


class CaptureReportTests(unittest.TestCase):
    def test_npm_index_rejects_missing_version_or_unknown_status(self):
        invalid_entries = [
            {'package': 'a'},
            {'package': 'a', 'resolved': '1.0.0'},
            {'package': 'a', 'resolved': '1.0.0', 'status': 'Unknown'},
        ]
        for entry in invalid_entries:
            with self.subTest(entry=entry), self.assertRaises(ValueError):
                report.npm_index({'dependencies': [entry]})

    def test_report_marks_missing_npm_version_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = root / 'data'
            first, last = data / '2026-11-12', data / '2026-11-13'
            first.mkdir(parents=True)
            last.mkdir()
            (root / 'candidates.txt').write_text('sample\thttps://example.test/sample\tnpm\n')
            for day in (first, last):
                (day / 'sample.npm.json').write_text(json.dumps({
                    'dependencies': [{'package': 'a'}],
                    'errors': [],
                }))
                (day / 'sample.npm.time').write_text('0.1')

            output = io.StringIO()
            with patch.object(report, 'HERE', root), patch.object(report, 'DATA', data), \
                    contextlib.redirect_stdout(output):
                result = report.main()

            self.assertEqual(result, 1)
            self.assertIn('INCOMPLETE sample npm report', output.getvalue())


if __name__ == '__main__':
    unittest.main()
