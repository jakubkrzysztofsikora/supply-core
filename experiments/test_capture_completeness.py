import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import time
import unittest

HERE = Path(__file__).parent


class CaptureCompletenessTests(unittest.TestCase):
    def make_experiment(self, directory, tracks, missing=False):
        root = Path(directory)
        shutil.copy2(HERE / 'run.sh', root / 'run.sh')
        shutil.copy2(HERE / 'capture-lock.sh', root / 'capture-lock.sh')
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

    def test_standalone_capture_respects_daily_lock(self):
        import fcntl

        with tempfile.TemporaryDirectory() as directory:
            root = self.make_experiment(directory, 'actions')
            capture = root / 'data' / '2099-01-02'
            capture.mkdir()
            sentinel = capture / 'previous.json'
            sentinel.write_text('previous capture')
            binary = self.make_binary(root, 'exit 1\n')
            with (root / 'data' / '.daily-capture.lock').open('a') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                result = self.run_capture(root, binary)
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(sentinel.exists(), 'concurrent capture deleted previous results')

    def test_nested_capture_reuses_parent_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_experiment(directory, 'actions')
            binary = self.make_binary(root, 'printf \'{"references":[],"findings":[]}\\n\'\n')
            env = dict(os.environ, SUPPLY_BIN=str(binary))
            env.pop('SUPPLY_DAILY_CAPTURE_LOCK_FD', None)
            result = subprocess.run(
                ['bash', '-c',
                 '. "$1/capture-lock.sh"; capture_lock "$1/data/.daily-capture.lock" || exit 1; '
                 'bash "$1/run.sh" 2099-01-02', '_', str(root)],
                env=env, capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue((root / 'data/2099-01-02/sample.actions.json').exists())

    def test_standalone_remote_scan_respects_daily_lock(self):
        import fcntl

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copy2(HERE / 'remote-scan.sh', root / 'remote-scan.sh')
            shutil.copy2(HERE / 'capture-lock.sh', root / 'capture-lock.sh')
            (root / 'data').mkdir()
            binary = root / 'kubectl'
            binary.write_text('#!/bin/sh\n: > "$FIXTURE_DIR/kubectl-called"\nexit 1\n')
            binary.chmod(0o755)
            env = dict(os.environ, PATH=f'{root}:{os.environ["PATH"]}',
                       FIXTURE_DIR=str(root), SUPPLY_SCAN_IMAGE='fixture')
            with (root / 'data' / '.daily-capture.lock').open('a') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                result = subprocess.run(
                    ['bash', str(root / 'remote-scan.sh'), 'day', 'findings', 'ledger'],
                    env=env, capture_output=True, text=True, timeout=10,
                )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root / 'kubectl-called').exists(), 'concurrent scan reached kubectl')

    def test_daily_capture_rejects_overlapping_runs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            experiments = root / 'experiments'
            experiments.mkdir()
            shutil.copy2(HERE / 'daily-capture.sh', experiments / 'daily-capture.sh')
            shutil.copy2(HERE / 'capture-lock.sh', experiments / 'capture-lock.sh')

            home_bin = root / 'home' / '.cargo' / 'bin'
            home_bin.mkdir(parents=True)
            for name in ('cargo', 'git'):
                tool = home_bin / name
                tool.write_text('#!/bin/sh\nexit 0\n')
                tool.chmod(0o755)

            run = experiments / 'run.sh'
            run.write_text(
                '#!/bin/sh\n'
                'if [ -e "$FIXTURE_DIR/started" ]; then\n'
                '  : > "$FIXTURE_DIR/overlap"\n'
                '  exit 1\n'
                'fi\n'
                ': > "$FIXTURE_DIR/started"\n'
                'while [ ! -e "$FIXTURE_DIR/release" ]; do sleep 0.1; done\n'
                'exit 1\n'
            )
            run.chmod(0o755)
            check = experiments / 'check.sh'
            check.write_text('#!/bin/sh\nexit 0\n')
            check.chmod(0o755)

            env = os.environ.copy()
            for key in ('SUPPLY_SCAN_IMAGE', 'SUPPLY_STATUS_URL', 'SUPPLY_STATUS_AUTH_TOKEN'):
                env.pop(key, None)
            env.update({
                'HOME': str(root / 'home'),
                'FIXTURE_DIR': str(root),
                'SUPPLY_STATUS_PUBLISH_ENV': str(root / 'missing.env'),
            })
            command = ['bash', str(experiments / 'daily-capture.sh')]
            first = subprocess.Popen(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic() + 10
                while not (root / 'started').exists() and time.monotonic() < deadline:
                    if first.poll() is not None:
                        self.fail('first capture exited before starting')
                    time.sleep(0.05)
                self.assertTrue((root / 'started').exists(), 'first capture did not start')

                second = subprocess.run(command, env=env, capture_output=True, text=True, timeout=10)
                self.assertNotEqual(second.returncode, 0)
                self.assertFalse((root / 'overlap').exists(), 'second capture started')
                self.assertIn('capture already running', second.stderr)
            finally:
                (root / 'release').touch()
                first.communicate(timeout=10)

            (root / 'started').unlink()
            third = subprocess.run(command, env=env, capture_output=True, text=True, timeout=10)
            self.assertTrue((root / 'started').exists(), third.stderr)


if __name__ == '__main__':
    unittest.main()
