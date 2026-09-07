import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

spec = importlib.util.spec_from_file_location('machine_eval', Path(__file__).with_name('machine_eval.py'))
evaluation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evaluation)


class EvaluationTests(unittest.TestCase):
    def test_yarn_classic_alias_transitive_and_custom_sources(self):
        raw = b'''# yarn lockfile v1
"alias@npm:@scope/real@^1", "@scope/real@^1":
  version "1.2.3"
  resolved "https://registry.yarnpkg.com/@scope/real/-/real-1.2.3.tgz#abc"
  dependencies:
    child "^2"
child@^2:
  version "2.0.0"
  resolved "https://registry.npmjs.org/child/-/child-2.0.0.tgz"
private@^1:
  version "1.0.0"
  resolved "https://registry.npmjs.org.evil.test/private/-/private-1.0.0.tgz"
git@*:
  version "1.0.0"
  resolved "git+https://example.test/repo"
'''
        pairs, gaps = evaluation.yarn_packages(raw)
        self.assertEqual(pairs, {('@scope/real', '1.2.3'), ('child', '2.0.0')})
        self.assertEqual(len(gaps), 2)
        for invalid in (b'__metadata:\n  version: 8', b'# yarn lockfile v1\n',
                        b'# yarn lockfile v1\ninvalid',
                        b'# yarn lockfile v1\na@1:\n  version "1"\n  version "2"'):
            with self.assertRaises(ValueError):
                evaluation.yarn_packages(invalid)

    def test_yarn_inventory_and_manifest_mapping(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / 'package.json').write_text('{}')
            (root / 'yarn.lock').write_text('# yarn lockfile v1\na@^1:\n  version "1.0.0"\n'
                '  resolved "https://registry.yarnpkg.com/a/-/a-1.0.0.tgz"\n')
            def git(args, timeout=30):
                return 'package.json\0yarn.lock\0Cargo.lock\0vendor/yarn.lock' if 'ls-files' in args else 'abc'
            with patch.object(evaluation, 'command', side_effect=git), patch.object(
                    evaluation.subprocess, 'run', return_value=SimpleNamespace(
                        returncode=0, stdout='{"references":[],"findings":[]}')):
                result = evaluation.inspect_repo(root, Path('/unused'))
            self.assertEqual(result['packages'], [['a', '1.0.0']])
            self.assertFalse(result['gaps'])
            self.assertFalse(result['errors'])
            self.assertEqual(len(result['input_inventory']), 4)
            self.assertTrue(result['input_inventory'][-1]['excluded'])
            (root / 'package.json').write_text('{"dependencies":{"a":"^1"}}')
            (root / 'yarn.lock').write_text('# yarn lockfile v1\n')
            with patch.object(evaluation, 'command', side_effect=git), patch.object(
                    evaluation.subprocess, 'run', return_value=SimpleNamespace(
                        returncode=0, stdout='{"references":[],"findings":[]}')):
                result = evaluation.inspect_repo(root, Path('/unused'))
            self.assertTrue(any('no resolutions' in error for error in result['errors']))
            self.assertTrue(any('not mapped' in gap for gap in result['gaps']))

    def test_missing_input_and_head_do_not_abort_remaining_inspection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / 'package-lock.json').write_text(json.dumps({
                'lockfileVersion': 3, 'packages': {'node_modules/a': {'version': '1.2.3'}}}))

            def git(args, timeout=30):
                if 'rev-parse' in args:
                    raise evaluation.subprocess.CalledProcessError(128, args)
                if 'ls-files' in args:
                    return 'missing/package.json\0package-lock.json\0'
                return ''

            with patch.object(evaluation, 'command', side_effect=git), patch.object(
                    evaluation.subprocess, 'run', return_value=SimpleNamespace(
                        returncode=0, stdout='{"references":[],"findings":[]}')) as scan:
                result = evaluation.inspect_repo(root, Path('/unused'))
            self.assertEqual(result['packages'], [['a', '1.2.3']])
            self.assertIsNone(result['commit'])
            self.assertEqual(len(result['errors']), 2)
            self.assertTrue(any('missing/package.json' in error for error in result['errors']))
            scan.assert_called_once()

    def test_unmapped_manifest_is_gap_even_with_root_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / 'apps/other').mkdir(parents=True)
            (root / 'package.json').write_text('{}')
            (root / 'apps/other/package.json').write_text('{}')
            (root / 'package-lock.json').write_text(json.dumps({'lockfileVersion': 3, 'packages': {'': {}}}))
            def git(args, timeout=30):
                if 'ls-files' in args:
                    return 'package.json\0apps/other/package.json\0package-lock.json'
                if 'status' in args:
                    return ''
                return 'abc'
            with patch.object(evaluation, 'command', side_effect=git), patch.object(
                    evaluation.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout='{"references":[],"findings":[]}')):
                result = evaluation.inspect_repo(root, Path('/unused'))
            self.assertTrue(any('apps/other/package.json' in gap for gap in result['gaps']))
            self.assertFalse(result['errors'])

    def test_failed_baseline_is_never_comparable_to_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / 'binary'
            binary.write_bytes(b'fixture')
            config = {'state': str(root / 'state'), 'roots': [str(root)], 'binary': str(binary)}
            report = {'path': str(root), 'packages': [['a', '1.0.0']], 'errors': [],
                      'gaps': [], 'duration_seconds': 0, 'actions': {'references': [], 'findings': []}}
            with patch.object(evaluation, 'discover', side_effect=lambda *args: ([root], [], [])), patch.object(
                    evaluation, 'inspect_repo', side_effect=lambda *args: json.loads(json.dumps(report))):
                with patch.object(evaluation, 'query_osv', return_value=({}, ['offline'])):
                    self.assertEqual(evaluation.run(config), 2)
                    self.assertFalse((root / 'state/baseline.json').exists())
                with patch.object(evaluation, 'query_osv', return_value=({'["a","1.0.0"]': ['GHSA-test']}, [])):
                    self.assertEqual(evaluation.run(config), 0)
            latest = json.loads((root / 'state/latest.json').read_text())
            self.assertFalse(latest['baseline_comparable'])
            self.assertEqual(latest['new_findings'], [])
            self.assertEqual(len(latest['findings']), 1)
            self.assertTrue((root / 'state/baseline.json').exists())

    def test_v3_nested_dev_alias_and_workspace(self):
        pairs, gaps = evaluation.npm_packages({'lockfileVersion': 3, 'packages': {
            '': {'name': 'private-root', 'version': '1.0.0'},
            'packages/app': {'name': 'private-app', 'version': '1.0.0'},
            'node_modules/a': {'version': '1.0.0', 'dev': True},
            'node_modules/a/node_modules/b': {'version': '2.0.0'},
            'node_modules/alias': {'name': '@scope/real', 'version': '3.0.0'},
            'node_modules/workspace': {'link': True},
            'node_modules/git': {'version': 'git+https://example.test/x'}}})
        self.assertEqual(pairs, {('a', '1.0.0'), ('b', '2.0.0'), ('@scope/real', '3.0.0')})
        self.assertEqual(len(gaps), 1)

    def test_v1_transitive_and_unknown_version(self):
        pairs, gaps = evaluation.npm_packages({'lockfileVersion': 1, 'dependencies': {
            'a': {'version': '1.2.3', 'dependencies': {'b': {'version': '2.0.0-beta.1'}}}}})
        self.assertEqual(pairs, {('a', '1.2.3'), ('b', '2.0.0-beta.1')})
        self.assertFalse(gaps)
        with self.assertRaises(ValueError):
            evaluation.npm_packages({'lockfileVersion': 99})

    def test_batch_cache_and_failure_never_becomes_clean(self):
        class Response:
            def __enter__(self):
                import io
                return io.StringIO('{"results":[{"vulns":[{"id":"GHSA-test"}]}]}')
            def __exit__(self, *args):
                pass
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            with patch.object(evaluation.urllib.request, 'urlopen', return_value=Response()) as request:
                result, errors = evaluation.query_osv({('a', '1.0.0')}, cache)
                self.assertFalse(errors)
                self.assertEqual(list(result.values()), [['GHSA-test']])
                evaluation.query_osv({('a', '1.0.0')}, cache)
                self.assertEqual(request.call_count, 1)
            with patch.object(evaluation.urllib.request, 'urlopen', side_effect=OSError('offline')):
                result, errors = evaluation.query_osv({('b', '2.0.0')}, cache)
                self.assertEqual(result, {})
                self.assertTrue(errors)

    def test_discovery_prunes_dependencies_and_reports_missing_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'repo/.git').mkdir(parents=True)
            (root / 'node_modules/vendor/.git').mkdir(parents=True)
            with patch.object(evaluation, 'command', return_value='.git'):
                found, duplicates, errors = evaluation.discover([str(root), str(root / 'missing')])
            self.assertEqual(found, [(root / 'repo').resolve()])
            self.assertFalse(duplicates)
            self.assertEqual(len(errors), 1)


if __name__ == '__main__':
    unittest.main()
