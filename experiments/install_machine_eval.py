#!/usr/bin/env python3
"""Install a versioned local scanner and daily macOS LaunchAgent."""
import hashlib
import argparse
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--home-scope', action='store_true', help='Set discovery root to the current home directory')
    parser.add_argument('--retire-legacy-cron', action='store_true', help='Back up crontab and remove only the old supply-core capture entry')
    args = parser.parse_args()
    source = Path(__file__).resolve().parent
    state = Path.home() / '.local/share/supply-core'
    state.mkdir(parents=True, exist_ok=True)
    state.chmod(0o700)
    binary = source.parent / 'target/release/supply-core'
    runner = source / 'machine_eval.py'
    digest = hashlib.sha256(binary.read_bytes() + runner.read_bytes()).hexdigest()[:16]
    release = state / 'releases' / digest
    release.mkdir(parents=True, exist_ok=True)
    shutil.copy2(binary, release / 'supply-core')
    shutil.copy2(runner, release / 'machine_eval.py')
    config_path = state / 'config.json'
    config = json.loads(config_path.read_text()) if config_path.exists() else {
        'roots': [str(Path.home())],
        'workers': 4, 'state': str(state)}
    config['binary'] = str(release / 'supply-core')
    if args.home_scope:
        config['roots'] = [str(Path.home())]
    if 'known_repositories' not in config:
        known = set()
        for inventory in (state / 'runs').glob('*/inventory.json'):
            known.update(json.loads(inventory.read_text()).get('repositories', []))
        config['known_repositories'] = sorted(known)
    config_path.write_text(json.dumps(config, indent=2) + '\n')
    label = 'com.supply-core.machine-evaluation'
    plist_path = Path.home() / 'Library/LaunchAgents' / f'{label}.plist'
    plist_path.parent.mkdir(parents=True, exist_ok=True)
    plist = {'Label': label,
        'ProgramArguments': [sys.executable, str(release / 'machine_eval.py'), '--config', str(config_path)],
        'StartCalendarInterval': {'Hour': 8, 'Minute': 30},
        'ProcessType': 'Standard',
        'EnvironmentVariables': {'HOME': str(Path.home()), 'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'},
        'StandardOutPath': str(state / 'launchd.log'), 'StandardErrorPath': str(state / 'launchd.err')}
    with plist_path.open('wb') as handle:
        plistlib.dump(plist, handle)
    domain = f'gui/{os.getuid()}'
    subprocess.run(['launchctl', 'bootout', f'{domain}/{label}'], capture_output=True)
    subprocess.run(['launchctl', 'bootstrap', domain, str(plist_path)], check=True)
    if args.retire_legacy_cron:
        current = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
        if current.returncode == 0:
            lines = current.stdout.splitlines(keepends=True)
            retained = [line for line in lines if '# supply-core-daily-capture' not in line]
            if retained != lines:
                key = hashlib.sha256(current.stdout.encode()).hexdigest()[:16]
                (state / f'crontab-before-machine-eval-{key}.txt').write_text(current.stdout)
                subprocess.run(['crontab', '-'], input=''.join(retained), text=True, check=True)
                print('Retired legacy supply-core cron entry; original crontab backed up in state directory')
    print(json.dumps({'config': str(config_path), 'release': str(release), 'launch_agent': str(plist_path)}, indent=2))


if __name__ == '__main__':
    main()
