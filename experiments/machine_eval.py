#!/usr/bin/env python3
"""Read-only repository evaluation. Never installs packages or runs project code."""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
import urllib.request
from urllib.parse import unquote, urlsplit

STATE = Path.home() / '.local/share/supply-core'
INPUT_NAMES = {'package.json', 'package-lock.json', 'npm-shrinkwrap.json',
               'yarn.lock', 'pnpm-lock.yaml', 'bun.lock', 'bun.lockb',
               'Cargo.toml', 'Cargo.lock', 'pyproject.toml', 'poetry.lock',
               'uv.lock', 'requirements.txt', 'go.mod', 'go.sum',
               'Gemfile', 'Gemfile.lock', 'composer.json', 'composer.lock',
               'packages.lock.json'}
PRUNE = {'.git', 'node_modules', 'target', '.venv', 'venv', '__pycache__',
         '.next', 'dist', 'build', 'Library', '.Trash', '.cache', '.npm',
         '.cargo', '.rustup', '.codex', '.claude', '.local', '.ssh', '.orbstack',
         '.bun', '.nuget', '.m2', '.gradle', '.terraform', '.yarn', '.pnpm-store',
         '.vscode', '.cursor', 'vendor', '.worktrees', 'worktrees', 'lustro-worktrees',
         'Applications', 'Pictures', 'Movies', 'Music', 'OrbStack'}


def command(args, timeout=30):
    if args[0] == 'git':
        args = ['git', '--no-optional-locks', '-c', 'core.fsmonitor=false'] + args[1:]
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                          check=True).stdout.strip()


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
    temporary.replace(path)


def discover(roots, known_repositories=()):
    found, errors, warnings = [], [], []
    for root in roots:
        print(f'Discovering Git repositories under {root}', flush=True)
        if not Path(root).is_dir():
            errors.append(f'missing scan root: {root}')
            continue
        for current, dirs, files in os.walk(root, followlinks=False,
                                            onerror=lambda e: warnings.append(str(e))):
            if '.git' in dirs or '.git' in files:
                found.append(Path(current).resolve())
                dirs[:] = []
            elif len(Path(current).relative_to(root).parts) >= 6:
                dirs[:] = []
            else:
                dirs[:] = [d for d in dirs if d not in PRUNE
                           and (not d.startswith('.') or d == '.deployer')]
    # Previously inventoried nested checkouts remain in scope without walking
    # millions of source/build directories every day.
    found.extend(Path(p).resolve() for p in known_repositories if (Path(p) / '.git').exists())
    for root in list(set(found)):
        try:
            entries = command(['git', '-C', str(root), 'ls-files', '--stage', '-z'])
            for entry in entries.split('\0'):
                if entry.startswith('160000 ') and '\t' in entry:
                    submodule = root / entry.split('\t', 1)[1]
                    if (submodule / '.git').exists():
                        found.append(submodule.resolve())
        except (OSError, subprocess.SubprocessError) as e:
            warnings.append(f'submodule discovery for {root}: {e}')
    selected, duplicates, common = [], [], {}
    # Prefer the primary checkout to its linked worktrees.
    for root in sorted(set(found), key=lambda p: (not (p / '.git').is_dir(), str(p))):
        try:
            gitdir = command(['git', '-C', str(root), 'rev-parse', '--git-common-dir'])
            key = str((root / gitdir).resolve())
            if key in common:
                duplicates.append({'path': str(root), 'selected': common[key],
                                   'reason': 'linked worktree excluded; its content may differ'})
            else:
                common[key] = str(root)
                selected.append(root)
        except (OSError, subprocess.SubprocessError) as e:
            warnings.append(f'{root}: {e}')
    excluded_paths = {d['path'] for d in duplicates}
    for root in selected:
        try:
            records = command(['git', '-C', str(root), 'worktree', 'list', '--porcelain', '-z'])
            for record in records.split('\0'):
                if record.startswith('worktree '):
                    path = str(Path(record[9:]).resolve())
                    if path != str(root) and path not in excluded_paths:
                        duplicates.append({'path': path, 'selected': str(root),
                                           'reason': 'linked worktree excluded; its content may differ'})
                        excluded_paths.add(path)
        except (OSError, subprocess.SubprocessError) as e:
            warnings.append(f'worktree inventory for {root}: {e}')
    return selected, duplicates, errors, warnings


def npm_packages(doc):
    """Return unique registry package/version pairs plus unassessed entries."""
    packages, gaps = set(), []

    def add(name, entry, location):
        version = entry.get('version', '')
        if entry.get('link'):
            return
        resolved = entry.get('resolved', '')
        if resolved and not resolved.startswith(('https://registry.npmjs.org/', 'https://registry.yarnpkg.com/')):
            gaps.append(f'{location}: custom/non-registry source not assessed')
            return
        if not isinstance(version, str) or not re.fullmatch(
                r'\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?', version):
            gaps.append(f'{location}: non-registry or missing version')
        elif not name or not isinstance(name, str):
            gaps.append(f'{location}: missing package identity')
        else:
            packages.add((name, version))

    if doc.get('lockfileVersion') in (2, 3):
        if not isinstance(doc.get('packages'), dict):
            raise ValueError('lockfile packages missing')
        for location, entry in doc['packages'].items():
            if 'node_modules/' not in location:
                continue  # workspace/root project, not an installed dependency
            add(entry.get('name') or location.rsplit('node_modules/', 1)[1], entry, location)
    elif doc.get('lockfileVersion') == 1:
        def walk(deps):
            for name, entry in deps.items():
                add(name, entry, name)
                walk(entry.get('dependencies', {}))
        walk(doc.get('dependencies', {}))
    else:
        raise ValueError('unsupported npm lockfile version')
    return packages, gaps


def yarn_packages(raw):
    """Read Classic registry resolutions without executing Yarn or project code."""
    text = raw.decode('utf-8')
    if '# yarn lockfile v1' not in text.splitlines()[:5]:
        raise ValueError('unsupported Yarn format (only Classic v1 is supported)')
    entries, current = [], None
    for line in text.splitlines():
        if not line.strip() or line.startswith('#'):
            continue
        if not line.startswith(' '):
            if not line.endswith(':'):
                raise ValueError('invalid Yarn entry header')
            current = {}
            entries.append(current)
        elif current is None:
            raise ValueError('Yarn field without entry')
        else:
            match = re.fullmatch(r'  (version|resolved) (.+)', line)
            if match:
                key, value = match.groups()
                if key in current:
                    raise ValueError('duplicate Yarn resolution field')
                current[key] = json.loads(value) if value.startswith('"') else value
    if not entries:
        raise ValueError('Yarn lockfile has no resolutions; dependency coverage is unknown')
    packages, gaps = set(), []
    for index, entry in enumerate(entries):
        location = f'entry {index + 1}'
        resolved = entry.get('resolved', '')
        if not isinstance(resolved, str):
            gaps.append(f'{location}: invalid resolution')
            continue
        url = urlsplit(resolved)
        if url.scheme != 'https' or url.netloc not in {'registry.npmjs.org', 'registry.yarnpkg.com'}:
            gaps.append(f'{location}: custom/non-registry source not assessed')
            continue
        # Use the resolved archive identity, not a potentially aliased selector.
        name = unquote(url.path).lstrip('/').split('/-/', 1)[0]
        if '/-/' not in url.path or not re.fullmatch(r'(?:@[A-Za-z0-9._-]+/)?[A-Za-z0-9._-]+', name):
            gaps.append(f'{location}: missing package identity')
            continue
        pairs, missing = npm_packages({'lockfileVersion': 1, 'dependencies': {name: entry}})
        packages.update(pairs)
        gaps.extend(missing)
    return packages, gaps


OSV_ECOSYSTEM = {'npm': 'npm', 'pypi': 'PyPI', 'nuget': 'NuGet'}
PACKAGE_ECOSYSTEMS = ('npm', 'pypi', 'nuget')


def normalize_pypi_name(raw):
    return re.sub(r'[-_.]+', '-', raw).lower()


def requirements_packages(text):
    """Read exact ==/=== pins from requirements.txt without resolving or installing."""
    packages, gaps = set(), []
    logical, logical_start = '', None
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.split('#', 1)[0].strip()
        if line.endswith('\\'):
            logical += line[:-1].strip() + ' '
            if logical_start is None:
                logical_start = number
            continue
        if logical:
            line = (logical + line).strip()
            start = logical_start
            logical, logical_start = '', None
        else:
            start = number
        if not line:
            continue
        tokens = line.split()
        unsupported = [t for t in tokens if t.startswith('-') and not t.startswith('--hash=')]
        if unsupported:
            gaps.append(f'line {start}: unsupported option')
            continue
        parts = [t for t in tokens if not t.startswith('-')]
        if not parts:
            continue
        requirement = ' '.join(parts)
        if '://' in requirement or requirement.startswith(('.', '/')):
            gaps.append(f'line {start}: non-registry requirement')
            continue
        if ';' in requirement:
            gaps.append(f'line {start}: environment marker not evaluated')
            continue
        if '===' in requirement:
            name_part, version_part = requirement.split('===', 1)
        elif '==' in requirement:
            name_part, version_part = requirement.split('==', 1)
        else:
            gaps.append(f'line {start}: not pinned with ==')
            continue
        name = normalize_pypi_name(name_part.split('[', 1)[0].strip())
        version = version_part.strip()
        if (not name or not version or any(ch.isspace() for ch in version)
                or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+!-]*', version)):
            gaps.append(f'line {start}: unparseable pin')
            continue
        packages.add((name, version))
    if logical:
        gaps.append('end of file: unterminated line continuation')
    return packages, gaps


def nuget_packages(doc):
    packages, gaps = set(), []
    dependencies = doc.get('dependencies')
    if not isinstance(dependencies, dict):
        raise ValueError('packages.lock.json dependencies missing')
    for target, entries in dependencies.items():
        if not isinstance(entries, dict):
            gaps.append(f'target {target}: dependencies are not an object')
            continue
        for name, details in entries.items():
            if not isinstance(details, dict):
                gaps.append(f'target {target}: {name} has invalid entry')
                continue
            resolved = details.get('resolved')
            if isinstance(resolved, str) and resolved:
                packages.add((name, resolved))
            elif details.get('type') != 'Project':
                gaps.append(f'target {target}: {name} has no resolved version')
    return packages, gaps


def inspect_repo(root, binary):
    started = time.monotonic()
    result = {'path': str(root), 'errors': [], 'gaps': [], 'packages': [],
              'manifests': [], 'lockfiles': [], 'input_hashes': {}, 'input_inventory': []}
    try:
        result['commit'] = None
        try:
            result['commit'] = command(['git', '-C', str(root), 'rev-parse', 'HEAD'])
        except subprocess.SubprocessError as e:
            result['gaps'].append(f'HEAD unavailable: {e}')
        result['dirty'] = bool(command(['git', '-C', str(root), 'status', '--porcelain',
                                        '--untracked-files=no']))
        paths = command(['git', '-C', str(root), 'ls-files', '-z']).split('\0')
        packages, covered_manifests = set(), set()
        for relative in paths:
            path = root / relative
            if relative and path.name in INPUT_NAMES:
                result['input_inventory'].append({'path': relative, 'kind': path.name,
                    'excluded': any(part in PRUNE for part in Path(relative).parts)})
            if not relative or any(part in PRUNE for part in Path(relative).parts):
                continue
            relevant = (path.name in {'package.json', 'package-lock.json', 'npm-shrinkwrap.json',
                                     'yarn.lock', 'pnpm-lock.yaml', 'bun.lock', 'bun.lockb',
                                     'requirements.txt', 'packages.lock.json'})
            if not relevant:
                continue
            if path.is_symlink() or not path.resolve().is_relative_to(root):
                result['gaps'].append(f'{relative}: symlink input excluded')
                continue
            try:
                if path.stat().st_size > 32 * 1024 * 1024:
                    result['gaps'].append(f'{relative}: exceeds 32 MiB input limit')
                    continue
                raw = path.read_bytes()
            except OSError as e:
                result['gaps'].append(f'{relative}: {e}')
                continue
            result['input_hashes'][relative] = hashlib.sha256(raw).hexdigest()
            if path.name == 'package.json':
                result['manifests'].append(relative)
            elif path.name in {'package-lock.json', 'npm-shrinkwrap.json'}:
                try:
                    doc = json.loads(raw)
                    pairs, gaps = npm_packages(doc)
                    packages.update(('npm', name, version) for name, version in pairs)
                    result['lockfiles'].append(relative)
                    covered_manifests.add(str(Path(relative).parent / 'package.json'))
                    for workspace in doc.get('packages', {}):
                        if workspace and 'node_modules/' not in workspace:
                            covered_manifests.add(str(Path(relative).parent / workspace / 'package.json'))
                    result['gaps'].extend(f'{relative}: {g}' for g in gaps)
                except (ValueError, TypeError, AttributeError) as e:
                    result['errors'].append(f'{relative}: {e}')
            elif path.name == 'yarn.lock':
                try:
                    pairs, gaps = yarn_packages(raw)
                    packages.update(('npm', name, version) for name, version in pairs)
                    result['lockfiles'].append(relative)
                    covered_manifests.add(str(Path(relative).parent / 'package.json'))
                    result['gaps'].extend(f'{relative}: {g}' for g in gaps)
                except (ValueError, TypeError) as e:
                    result['errors'].append(f'{relative}: {e}')
            elif path.name == 'requirements.txt':
                try:
                    pairs, gaps = requirements_packages(raw.decode('utf-8'))
                    packages.update(('pypi', name, version) for name, version in pairs)
                    result['lockfiles'].append(relative)
                    result['gaps'].extend(f'{relative}: {g}' for g in gaps)
                except (UnicodeDecodeError, ValueError, TypeError) as e:
                    result['errors'].append(f'{relative}: {e}')
            elif path.name == 'packages.lock.json':
                try:
                    pairs, gaps = nuget_packages(json.loads(raw))
                    packages.update(('nuget', name, version) for name, version in pairs)
                    result['lockfiles'].append(relative)
                    result['gaps'].extend(f'{relative}: {g}' for g in gaps)
                except (ValueError, TypeError) as e:
                    result['errors'].append(f'{relative}: {e}')
            elif path.name in {'pnpm-lock.yaml', 'bun.lock', 'bun.lockb'}:
                result['gaps'].append(f'{relative}: unsupported lockfile format')
        for manifest in result['manifests']:
            if manifest not in covered_manifests:
                result['gaps'].append(f'{manifest}: not mapped to a supported lockfile/workspace')
        result['packages'] = [list(p) for p in sorted(packages)]
        if (root / '.github').is_symlink() or (root / '.github/workflows').is_symlink():
            raise ValueError('workflow directory symlink excluded')
        workflow_bytes = 0
        for path in (root / '.github/workflows').rglob('*'):
            if path.is_symlink() or not path.is_file() or path.suffix not in ('.yml', '.yaml'):
                continue
            size = path.stat().st_size
            workflow_bytes += size
            if size > 32 * 1024 * 1024 or workflow_bytes > 64 * 1024 * 1024:
                raise ValueError('workflow inputs exceed evaluation size limit')
            result['input_hashes'][str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
        scan = subprocess.run([str(binary), 'scan-actions', str(root), '--json'],
                              capture_output=True, text=True, timeout=60)
        if scan.returncode not in (0, 2):
            result['errors'].append('workflow scan: ' + scan.stderr.strip()[:2000])
        else:
            result['actions'] = json.loads(scan.stdout)
        if not result['manifests'] and not result.get('actions', {}).get('references'):
            result['gaps'].append('no supported package manifests or Action references found')
        if result['commit'] is not None and result['commit'] != command(['git', '-C', str(root), 'rev-parse', 'HEAD']):
            result['errors'].append('HEAD changed during evaluation')
    except (OSError, ValueError, subprocess.SubprocessError) as e:
        result['gaps'].append(f'repository could not be read: {e}')
    result['duration_seconds'] = round(time.monotonic() - started, 2)
    return result


def query_osv(pairs, cache):
    results, errors, pending = {}, [], []
    now = time.time()
    for pair in sorted(pairs):
        key = json.dumps(pair, separators=(',', ':'))
        path = cache / (hashlib.sha256(key.encode()).hexdigest() + '.json')
        try:
            item = json.loads(path.read_text())
            if 0 <= now - item['fetched_at'] < 86400 and isinstance(item['ids'], list):
                results[key] = item['ids']
                continue
        except (OSError, ValueError, KeyError, TypeError):
            pass
        pending.append((pair, key, path))
    consecutive_failures = 0
    for start in range(0, len(pending), 100):
        chunk = pending[start:start + 100]
        request = urllib.request.Request('https://api.osv.dev/v1/querybatch',
            data=json.dumps({'queries': [
                {'package': {'ecosystem': OSV_ECOSYSTEM.get(p[0], p[0]), 'name': p[1]},
                 'version': p[2]} for p, _, _ in chunk]}).encode(),
            headers={'Content-Type': 'application/json', 'User-Agent': 'supply-core-evaluation/1'})
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                docs = json.load(response)['results']
            if len(docs) != len(chunk):
                raise ValueError('OSV batch response count mismatch')
            consecutive_failures = 0
            for (_, key, path), doc in zip(chunk, docs):
                if doc.get('next_page_token'):
                    errors.append(f'{key}: paginated OSV result requires follow-up')
                    continue
                ids = sorted({v['id'] for v in doc.get('vulns', [])})
                results[key] = ids
                write_json(path, {'fetched_at': now, 'ids': ids})
        except (OSError, ValueError, KeyError, TypeError) as e:
            errors.append(f'OSV batch {start}: {e}')
            consecutive_failures += 1
            if consecutive_failures >= 3:
                errors.append('OSV unavailable after three batches; remaining versions are unassessed')
                break
        print(f'OSV {min(start + 100, len(pending))}/{len(pending)} uncached pairs', flush=True)
    return results, errors


def run(config, inventory_only=False):
    state = Path(config['state']).expanduser()
    state.mkdir(parents=True, exist_ok=True)
    with (state / 'evaluation.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SystemExit('evaluation already running')
        started = datetime.now(timezone.utc).isoformat()
        run_dir = state / 'runs' / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
        run_dir.mkdir(parents=True)
        roots, excluded, errors, warnings = discover(config['roots'], config.get('known_repositories', []))
        inventory = {'roots': config['roots'], 'repositories': [str(r) for r in roots],
                     'excluded_worktrees': excluded, 'errors': errors,
                     'discovery_warnings': warnings,
                     'excluded_directories': sorted(PRUNE), 'tracked_ecosystems': list(PACKAGE_ECOSYSTEMS),
                     'workflow_inputs': 'working-tree .github/workflows files'}
        inventory['nested_repository_scope'] = 'registered submodules and configured known_repositories; source trees are pruned'
        inventory['discovery_depth_limit'] = 6
        inventory['hidden_directory_policy'] = 'skip hidden directories except .git markers and .deployer'
        write_json(run_dir / 'inventory.json', inventory)
        print(f'Discovered {len(roots)} repositories; {len(excluded)} linked worktrees excluded', flush=True)
        if inventory_only:
            print(run_dir)
            return 0
        binary = Path(config['binary'])
        binary_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
        runner_hash = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        reports = []
        with ThreadPoolExecutor(max_workers=config.get('workers', 4)) as pool:
            for report in pool.map(lambda root: inspect_repo(root, binary), roots):
                reports.append(report)
                key = hashlib.sha256(report['path'].encode()).hexdigest()[:16]
                write_json(run_dir / 'repos' / f'{key}.json', report)
                print(f'Inspected {len(reports)}/{len(roots)}: {report["path"]}', flush=True)
        pairs = {tuple(p) for report in reports for p in report['packages']}
        input_inventory = [{'repo': r['path'], 'inputs': r.get('input_inventory', []),
                            'mapped_lockfiles': r.get('lockfiles', []),
                            'gaps': r['gaps'], 'errors': r['errors']} for r in reports]
        write_json(run_dir / 'input-inventory.json', input_inventory)
        input_counts = Counter(i['kind'] for r in reports for i in r.get('input_inventory', [])
                               if not i['excluded'])
        osv, osv_errors = query_osv(pairs, state / 'cache' / 'osv-batch-v1')
        errors.extend(osv_errors)
        findings = []
        for report in reports:
            for pair in report['packages']:
                key = json.dumps(pair, separators=(',', ':'))
                if key not in osv:
                    report['errors'].append(
                        f'OSV not evaluated: {pair[0]}:{pair[1]}@{pair[2]}')
                for advisory in osv.get(key, []):
                    findings.append({'repo': report['path'], 'kind': f'{pair[0]}-advisory',
                                     'ecosystem': pair[0], 'package': pair[1],
                                     'version': pair[2], 'id': advisory})
            counts = Counter(r['raw'] for r in report.get('actions', {}).get('references', [])
                             if r['pin_kind'] not in ('FullSha', 'Local'))
            for raw, count in counts.items():
                findings.append({'repo': report['path'], 'kind': 'action-policy',
                                 'reference': raw, 'occurrences': count})
            errors.extend(f'{report["path"]}: {e}' for e in report['errors'])
            key = hashlib.sha256(report['path'].encode()).hexdigest()[:16]
            write_json(run_dir / 'repos' / f'{key}.json', report)
        baseline_path = state / 'baseline.json'
        previous = json.loads(baseline_path.read_text()) if baseline_path.exists() else None
        identities = {json.dumps(f, sort_keys=True) for f in findings}
        baseline_ids = {json.dumps(f, sort_keys=True) for f in previous['findings']} if previous else set()
        comparable = (previous is not None and previous['binary_sha256'] == binary_hash
                      and previous.get('runner_sha256') == runner_hash
                      and previous['inventory']['roots'] == config['roots']
                      and not previous['errors'] and not errors)
        summary = {'started_at': started, 'finished_at': datetime.now(timezone.utc).isoformat(),
            'run_directory': str(run_dir), 'binary_sha256': binary_hash,
            'runner_sha256': runner_hash, 'inventory': inventory,
            'repository_count': len(reports),
            'unique_npm_versions': len([p for p in pairs if p[0] == 'npm']),
            'unique_pip_versions': len([p for p in pairs if p[0] == 'pypi']),
            'unique_nuget_versions': len([p for p in pairs if p[0] == 'nuget']),
            'tracked_input_counts': dict(input_counts),
            'per_repository': [{'path': r['path'], 'package_versions': len(r['packages']),
                               'workflow_references': len(r.get('actions', {}).get('references', [])),
                               'workflow_findings': len(r.get('actions', {}).get('findings', [])),
                               'duration_seconds': r['duration_seconds'],
                               'errors': len(r['errors']), 'gaps': len(r['gaps'])} for r in reports],
            'osv_evaluated_versions': len(osv), 'findings': findings,
            'errors': errors, 'discovery_warnings': warnings,
            'gaps': [{'repo': r['path'], 'details': r['gaps']} for r in reports if r['gaps']],
            'new_findings': [json.loads(f) for f in sorted(identities - baseline_ids)] if comparable else [],
            'baseline_comparable': comparable,
            'repositories_removed_since_baseline': sorted(set(previous['inventory']['repositories']) - set(inventory['repositories'])) if previous else [],
            'baseline': previous['run_directory'] if previous else None,
            'limitations': ['OSV advisory matches are not malware detections or severity-filtered blocks',
                'Lockfile contents are declarations, not proof of installed bytes',
                'No quarantine-age, upstream update, or artifact-integrity evaluation in this run',
                'Other package ecosystems (RubyGems, Cargo, Maven, Go) and untracked inputs are not evaluated']}
        write_json(run_dir / 'summary.json', summary)
        lines = ['# Machine evaluation', '', f'Repositories: {len(reports)}',
            f'Unique npm: {summary["unique_npm_versions"]}; pip: {summary["unique_pip_versions"]}; '
            f'nuget: {summary["unique_nuget_versions"]}; OSV evaluated: {len(osv)}',
            f'Finding records: {len(findings)}; errors: {len(errors)}; repositories with gaps: {len(summary["gaps"])}',
            '', '## Tracked input inventory', '',
            json.dumps(dict(input_counts), sort_keys=True),
            'Per-repository paths and excluded inputs: input-inventory.json',
            '', '## Findings', '']
        lines.extend('- ' + json.dumps(f, ensure_ascii=True) for f in findings)
        lines.extend(['', '## Errors', ''] + ['- ' + e for e in errors])
        lines.extend(['', '## Discovery warnings', ''] + ['- ' + w for w in warnings])
        lines.extend(['', '## Coverage gaps', ''] + ['- ' + json.dumps(g) for g in summary['gaps']])
        (run_dir / 'report.md').write_text('\n'.join(lines) + '\n')
        # Preserve failed bootstrap baselines from older versions as evidence.
        if previous and previous['errors'] and not errors and reports:
            archived = baseline_path.with_name('baseline-incomplete-' + run_dir.name + '.json')
            baseline_path.replace(archived)
            previous = None
        if previous is None and not errors and reports:
            write_json(baseline_path, summary)
        write_json(state / 'latest.json', summary)
        print(f'Report: {run_dir / "report.md"}', flush=True)
        return 2 if errors else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=STATE / 'config.json')
    parser.add_argument('--inventory-only', action='store_true')
    args = parser.parse_args()
    raise SystemExit(run(json.loads(args.config.read_text()), args.inventory_only))


if __name__ == '__main__':
    main()
