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
            self.assertEqual(result['packages'], [['npm', 'a', '1.0.0']])
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

    def test_excluded_package_inputs_do_not_create_assessment_gap(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            vendor = root / 'vendor'
            vendor.mkdir()
            (vendor / 'package.json').write_text('{}')
            (vendor / 'package-lock.json').write_text('{}')

            def git(args, timeout=30):
                if 'ls-files' in args:
                    return 'vendor/package.json\0vendor/package-lock.json'
                if 'status' in args:
                    return ''
                return 'abc'

            with patch.object(evaluation, 'command', side_effect=git), patch.object(
                    evaluation.subprocess, 'run', return_value=SimpleNamespace(
                        returncode=0, stdout='{"references":[],"findings":[]}')):
                result = evaluation.inspect_repo(root, Path('/unused'))

            self.assertEqual(result['packages'], [])
            self.assertEqual(len(result['input_inventory']), 2)
            self.assertTrue(all(item['excluded'] for item in result['input_inventory']))
            self.assertFalse(result['gaps'])
            self.assertFalse(result['errors'])

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
            self.assertEqual(result['packages'], [['npm', 'a', '1.2.3']])
            self.assertIsNone(result['commit'])
            self.assertFalse(result['errors'])
            self.assertEqual(len(result['gaps']), 3)
            self.assertTrue(any('missing/package.json' in gap for gap in result['gaps']))
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

    def test_untracked_nuget_lock_does_not_cover_tracked_project(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / 'Project.csproj').write_text('<Project />')
            (root / 'packages.lock.json').write_text('{"dependencies": {}}')

            def git(args, timeout=30):
                if 'ls-files' in args:
                    return 'Project.csproj'
                if 'status' in args:
                    return ''
                return 'abc'

            with patch.object(evaluation, 'command', side_effect=git), patch.object(
                    evaluation.subprocess, 'run', return_value=SimpleNamespace(
                        returncode=0, stdout='{"references":[],"findings":[]}')):
                result = evaluation.inspect_repo(root, Path('/unused'))

            self.assertTrue(any(
                'Project.csproj' in gap and 'tracked packages.lock.json' in gap
                for gap in result['gaps']
            ))

    def test_tracked_workflow_missing_from_worktree_is_a_coverage_gap(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / 'package.json').write_text('{}')
            (root / 'package-lock.json').write_text(json.dumps({
                'lockfileVersion': 3,
                'packages': {'': {}, 'node_modules/a': {'version': '1.2.3'}},
            }))
            (root / '.github/workflows').mkdir(parents=True)

            def git(args, timeout=30):
                if 'ls-files' in args:
                    return 'package.json\0package-lock.json\0.github/workflows/deploy.yml'
                if 'status' in args:
                    return ''
                return 'abc'

            with patch.object(evaluation, 'command', side_effect=git), patch.object(
                    evaluation.subprocess, 'run', return_value=SimpleNamespace(
                        returncode=0, stdout='{"references":[],"findings":[]}')):
                result = evaluation.inspect_repo(root, Path('/unused'))

            self.assertTrue(any(
                '.github/workflows/deploy.yml' in gap and 'missing from working tree' in gap
                for gap in result['gaps']
            ))

    def test_workflow_without_action_references_is_still_assessed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            workflows = root / '.github/workflows'
            workflows.mkdir(parents=True)
            (workflows / 'ci.yml').write_text(
                'name: ci\non: push\njobs:\n  test:\n    steps:\n      - run: echo ok\n'
            )

            def git(args, timeout=30):
                if 'ls-files' in args:
                    return '.github/workflows/ci.yml'
                if 'status' in args:
                    return ''
                return 'abc'

            actions = {'references': [], 'findings': []}
            with patch.object(evaluation, 'command', side_effect=git), patch.object(
                    evaluation.subprocess, 'run', return_value=SimpleNamespace(
                        returncode=0, stdout=json.dumps(actions))):
                result = evaluation.inspect_repo(root, Path('/unused'))

            self.assertEqual(result['actions'], actions)
            self.assertFalse(result['errors'])
            self.assertFalse(result['gaps'])

    def test_workflow_symlink_is_a_coverage_gap(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            workflows = root / '.github/workflows'
            workflows.mkdir(parents=True)
            regular = workflows / 'ci.yml'
            regular.write_text('name: ci')
            (workflows / 'linked.yml').symlink_to(regular)

            def git(args, timeout=30):
                if 'ls-files' in args:
                    return '.github/workflows/ci.yml\0.github/workflows/linked.yml'
                if 'status' in args:
                    return ''
                return 'abc'

            actions = json.dumps({
                'references': [{'file': 'ci.yml', 'line': 1, 'raw': 'actions/checkout@abc',
                                'pin_kind': 'FullSha'}],
                'findings': [],
            })
            with patch.object(evaluation, 'command', side_effect=git), patch.object(
                    evaluation.subprocess, 'run', return_value=SimpleNamespace(
                        returncode=0, stdout=actions)):
                result = evaluation.inspect_repo(root, Path('/unused'))

            self.assertTrue(any('linked.yml' in gap for gap in result['gaps']))

    def test_old_incomplete_baseline_is_not_comparable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / 'binary'
            binary.write_bytes(b'fixture')
            state = root / 'state'
            state.mkdir()
            evaluation.write_json(state / 'baseline.json', {
                'errors': [], 'gaps': [{'repo': 'old', 'details': ['missing lock']}],
                'discovery_warnings': [], 'repository_count': 1, 'findings': [{'old': True}],
                'binary_sha256': 'same', 'runner_sha256': 'same',
                'inventory': {'roots': [str(root)], 'repositories': []}, 'run_directory': 'old'})
            report = {'path': str(root), 'packages': [], 'errors': [], 'gaps': [],
                      'duration_seconds': 0, 'actions': {'references': [], 'findings': []}}
            config = {'state': str(state), 'roots': [str(root)], 'binary': str(binary)}
            with patch.object(evaluation, 'discover', return_value=([root], [], [], [])), patch.object(
                    evaluation, 'inspect_repo', return_value=report), patch.object(
                    evaluation, 'query_osv', return_value=({}, [])):
                self.assertEqual(evaluation.run(config), 0)
            summary = json.loads((state / 'latest.json').read_text())
            self.assertTrue(summary['complete'])
            self.assertFalse(summary['baseline_comparable'])
            self.assertEqual(summary['new_findings'], [])

    def test_complete_advisory_scan_is_observational(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / 'binary'
            binary.write_bytes(b'fixture')
            report = {'path': str(root), 'packages': [['npm', 'a', '1.0.0']], 'errors': [],
                      'gaps': [], 'duration_seconds': 0,
                      'actions': {'references': [], 'findings': []}}
            config = {'state': str(root / 'state'), 'roots': [str(root)], 'binary': str(binary)}
            with patch.object(evaluation, 'discover', return_value=([root], [], [], [])), patch.object(
                    evaluation, 'inspect_repo', return_value=report), patch.object(
                    evaluation, 'query_osv', return_value=({'["npm","a","1.0.0"]': ['GHSA-test']}, [])):
                self.assertEqual(evaluation.run(config), 0)
            latest = json.loads((root / 'state/latest.json').read_text())
            self.assertTrue(latest['complete'])
            self.assertEqual(len(latest['findings']), 1)
            markdown = Path(latest['run_directory']) / 'report.md'
            self.assertIn('observational', markdown.read_text())
            self.assertIn('\n## Tracked input inventory\n', markdown.read_text())

    def test_malformed_workflow_json_and_scanner_failure_are_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / '.github/workflows').mkdir(parents=True)
            (root / '.github/workflows/ci.yml').write_text('name: ci')
            def git(args, timeout=30):
                if 'ls-files' in args:
                    return '.github/workflows/ci.yml'
                return 'abc'
            for code, output, expected in ((0, '{', 'workflow JSON invalid'),
                                           (3, '', 'workflow scanner failed')):
                with patch.object(evaluation, 'command', side_effect=git), patch.object(
                        evaluation.subprocess, 'run', return_value=SimpleNamespace(
                            returncode=code, stdout=output, stderr='scanner broke')):
                    result = evaluation.inspect_repo(root, Path('/unused'))
                self.assertTrue(any(expected in error for error in result['errors']))
                self.assertFalse(any('could not be read' in gap for gap in result['gaps']))
    def test_failed_baseline_is_never_comparable_to_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / 'binary'
            binary.write_bytes(b'fixture')
            config = {'state': str(root / 'state'), 'roots': [str(root)], 'binary': str(binary)}
            report = {'path': str(root), 'packages': [['npm', 'a', '1.0.0']], 'errors': [],
                      'gaps': [], 'duration_seconds': 0, 'actions': {'references': [], 'findings': []}}
            with patch.object(evaluation, 'discover', side_effect=lambda *args: ([root], [], [], [])), patch.object(
                    evaluation, 'inspect_repo', side_effect=lambda *args: json.loads(json.dumps(report))):
                with patch.object(evaluation, 'query_osv', return_value=({}, ['offline'])):
                    self.assertEqual(evaluation.run(config), 2)
                    self.assertFalse((root / 'state/baseline.json').exists())
                with patch.object(evaluation, 'query_osv', return_value=({'["npm","a","1.0.0"]': ['GHSA-test']}, [])):
                    self.assertEqual(evaluation.run(config), 0)
            latest = json.loads((root / 'state/latest.json').read_text())
            self.assertFalse(latest['baseline_comparable'])
            self.assertEqual(latest['new_findings'], [])
            self.assertEqual(len(latest['findings']), 1)
            self.assertTrue((root / 'state/baseline.json').exists())

    def test_requirements_parser(self):
        text = (
            "# comment\n"
            "requests==2.32.3\n"
            "Django[argon2]==4.2.11  # pinned\n"
            "flask>=3.0\n"
            "numpy==1.26.4 ; python_version < '3.13'\n"
            "-r extra.txt\n"
            "urllib3==2.5.0 \\\n    --hash=sha256:abc\n"
            "git+https://example.test/x.git\n"
        )
        pairs, gaps = evaluation.requirements_packages(text)
        self.assertEqual(
            pairs,
            {('requests', '2.32.3'), ('django', '4.2.11'), ('urllib3', '2.5.0')},
        )
        self.assertGreaterEqual(len(gaps), 4)

    def test_nuget_parser(self):
        doc = {'version': 1, 'dependencies': {
            'net8.0': {
                'Newtonsoft.Json': {'type': 'Direct', 'resolved': '13.0.3'},
                'MyProject': {'type': 'Project'},
                'RangeOnly': {'type': 'Direct', 'requested': '[1.0.0, )'},
            },
            'net8.0/win-x64': {
                'Newtonsoft.Json': {'type': 'Direct', 'resolved': '13.0.3'},
            },
        }}
        pairs, gaps = evaluation.nuget_packages(doc)
        self.assertEqual(pairs, {('Newtonsoft.Json', '13.0.3')})
        self.assertEqual(len(gaps), 1)
        with self.assertRaises(ValueError):
            evaluation.nuget_packages({})

    def test_ecosystem_inputs_are_evaluated(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / 'requirements.txt').write_text('requests==2.32.3\n')
            (root / 'packages.lock.json').write_text(json.dumps({
                'version': 1,
                'dependencies': {'net8.0': {'Serilog': {'type': 'Transitive', 'resolved': '3.1.1'}}},
            }))

            def git(args, timeout=30):
                if 'ls-files' in args:
                    return 'requirements.txt\0packages.lock.json\0'
                return 'abc'

            with patch.object(evaluation, 'command', side_effect=git), patch.object(
                    evaluation.subprocess, 'run', return_value=SimpleNamespace(
                        returncode=0, stdout='{"references":[],"findings":[]}')):
                result = evaluation.inspect_repo(root, Path('/unused'))
            self.assertEqual(result['packages'], [
                ['nuget', 'Serilog', '3.1.1'],
                ['pypi', 'requests', '2.32.3'],
            ])
            self.assertFalse(result['errors'])

    def test_osv_batch_sends_ecosystems(self):
        sent = []

        def fake_urlopen(request, timeout=None):
            body = json.loads(request.data)
            sent.append(body)
            text = json.dumps({'results': [{'vulns': []} for _ in body['queries']]})

            class Response:
                def __enter__(self):
                    import io
                    return io.StringIO(text)

                def __exit__(self, *args):
                    pass

            return Response()

        with tempfile.TemporaryDirectory() as directory:
            with patch.object(evaluation.urllib.request, 'urlopen', side_effect=fake_urlopen):
                evaluation.query_osv(
                    {('pypi', 'requests', '2.32.3'), ('nuget', 'Serilog', '3.1.1')},
                    Path(directory),
                )
        ecosystems = sorted(query['package']['ecosystem'] for query in sent[0]['queries'])
        self.assertEqual(ecosystems, ['NuGet', 'PyPI'])

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
                result, errors = evaluation.query_osv({('npm', 'a', '1.0.0')}, cache)
                self.assertFalse(errors)
                self.assertEqual(list(result.values()), [['GHSA-test']])
                evaluation.query_osv({('npm', 'a', '1.0.0')}, cache)
                self.assertEqual(request.call_count, 1)
            with patch.object(evaluation.urllib.request, 'urlopen', side_effect=OSError('offline')):
                result, errors = evaluation.query_osv({('npm', 'b', '2.0.0')}, cache)
                self.assertEqual(result, {})
                self.assertTrue(errors)

    def test_discovery_prunes_dependencies_and_reports_missing_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'repo/.git').mkdir(parents=True)
            (root / 'node_modules/vendor/.git').mkdir(parents=True)
            with patch.object(evaluation, 'command', return_value='.git'):
                found, duplicates, errors, warnings = evaluation.discover([str(root), str(root / 'missing')])
            self.assertEqual(found, [(root / 'repo').resolve()])
            self.assertFalse(duplicates)
            self.assertEqual(len(errors), 1)
            self.assertFalse(warnings)

    def test_discovery_io_noise_is_a_warning_not_an_error(self):
        def failing_walk(root, followlinks=False, onerror=None):
            if onerror is not None:
                onerror(OSError(5, 'Input/output error', root))
            return iter(())
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(evaluation.os, 'walk', side_effect=failing_walk):
                found, duplicates, errors, warnings = evaluation.discover([directory])
            self.assertFalse(found)
            self.assertFalse(duplicates)
            self.assertFalse(errors)
            self.assertTrue(any('Input/output error' in warning for warning in warnings))

    def test_discovery_submodule_failure_is_a_warning_not_an_error(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'repo/.git').mkdir(parents=True)

            def git(args, timeout=30):
                if 'ls-files' in args:
                    raise evaluation.subprocess.CalledProcessError(128, args)
                if 'rev-parse' in args:
                    return '.git'
                return ''

            with patch.object(evaluation, 'command', side_effect=git):
                found, duplicates, errors, warnings = evaluation.discover([str(root)])
            self.assertEqual(found, [(root / 'repo').resolve()])
            self.assertFalse(errors)
            self.assertTrue(any('submodule discovery' in warning for warning in warnings))


if __name__ == '__main__':
    unittest.main()
