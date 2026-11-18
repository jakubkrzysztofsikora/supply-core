import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest

HERE = Path(__file__).parent


class CaptureCompletenessTests(unittest.TestCase):
    def make_experiment(self, directory, tracks, missing=False):
        root = Path(directory)
        shutil.copy2(HERE / 'run.sh', root / 'run.sh')
        shutil.copy2(HERE / 'report.py', root / 'report.py')
        shutil.copy2(HERE / 'capture_validation.py', root / 'capture_validation.py')
        candidate = root / ('missing-candidate' if missing else 'candidate')
        if not missing:
            candidate.mkdir()
        (root / 'candidates.txt').write_text(f'sample\t{candidate}\t{tracks}\n')
        (root / 'data').mkdir()
        return root

    def make_binary(self, root, body):
        binary = root / 'supply-core'
        binary.write_text('#!/bin/sh\n' + body)
        binary.chmod(0o755)
        return binary

    def run_capture(self, root, binary):
        env = os.environ.copy()
        env['SUPPLY_BIN'] = str(binary)
        return subprocess.run(
            ['bash', str(root / 'run.sh'), '2099-01-02'],
            check=False, capture_output=True, text=True, env=env,
        )

    def test_malformed_npm_dependency_fails_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_experiment(directory, 'npm')
            npm_report = json.dumps({
                'dependencies': [{'package': 'a', 'status': 'Unknown'}],
                'errors': [],
            })
            binary = self.make_binary(root, f'printf "%s\\n" {shlex.quote(npm_report)}\n')

            result = self.run_capture(root, binary)

            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn('FAIL sample npm snapshot is incomplete', result.stdout)

    def test_action_findings_are_captured_without_failing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_experiment(directory, 'actions')
            action_json = json.dumps({'references': [], 'findings': [{'rule': 'pin'}]})
            binary = self.make_binary(root, (
                'if [ "$1" = "scan-actions" ]; then\n'
                f'  printf "%s\\n" {shlex.quote(action_json)}\n'
                '  exit 2\n'
                'fi\nexit 0\n'
            ))

            result = self.run_capture(root, binary)

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            captured = json.loads((root / 'data/2099-01-02/sample.actions.json').read_text())
            self.assertEqual(captured['findings'], [{'rule': 'pin'}])
            self.assertIn('CAPTURED actions references=0 findings=1', result.stdout)

    def test_malformed_action_report_fails_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_experiment(directory, 'actions')
            binary = self.make_binary(root, (
                'if [ "$1" = "scan-actions" ]; then\n'
                '  printf "{}\\n"\n'
                '  exit 2\n'
                'fi\nexit 0\n'
            ))

            result = self.run_capture(root, binary)

            self.assertEqual(result.returncode, 1)
            self.assertIn('INCOMPLETE sample actions snapshot', result.stdout)

    def test_missing_candidate_and_report_capture_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_experiment(directory, 'actions', missing=True)
            binary = self.make_binary(root, 'exit 0\n')

            result = self.run_capture(root, binary)

            self.assertEqual(result.returncode, 1)
            self.assertIn('INCOMPLETE sample (missing candidate:', result.stdout)
            self.assertNotIn('no candidates found', result.stdout)

            for day in ('2099-01-01', '2099-01-02'):
                (root / 'data' / day).mkdir(exist_ok=True)
            report = subprocess.run(
                ['python3', str(root / 'report.py')],
                check=False, capture_output=True, text=True,
            )
            self.assertEqual(report.returncode, 1)
            self.assertIn('INCOMPLETE sample actions', report.stdout)

    def test_report_accepts_complete_capture_pairs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_experiment(directory, 'actions')
            for day in ('2099-01-01', '2099-01-02'):
                capture = root / 'data' / day
                capture.mkdir()
                (capture / 'sample.actions.json').write_text(
                    json.dumps({'references': [], 'findings': []})
                )
                (capture / 'sample.actions.time').write_text('0.10\n')

            report = subprocess.run(
                ['python3', str(root / 'report.py')],
                check=False, capture_output=True, text=True,
            )

            self.assertEqual(report.returncode, 0, report.stdout + report.stderr)
            self.assertIn('## sample (actions) - 0 -> 0 refs', report.stdout)


if __name__ == '__main__':
    unittest.main()
