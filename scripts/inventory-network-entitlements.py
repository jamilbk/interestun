#!/usr/bin/env python3
"""Read-only inventory of network-related entitlements in installed Mach-O files.

Does not execute inspected binaries, load extensions, or contact their services.
Outputs only selected entitlement keys; inaccessible paths are recorded.
"""
import concurrent.futures
import json
import os
from pathlib import Path
import plistlib
import stat
import subprocess
import time

ROOTS = [
    '/System/Library', '/System/Applications', '/System/DriverKit',
    '/System/iOSSupport', '/System/Cryptexes', '/System/Developer',
    '/AppleInternal', '/Developer', '/usr', '/bin', '/sbin',
    '/Library', '/Applications', '/opt', str(Path.home() / 'Applications'),
]
MAGICS = {bytes.fromhex(h) for h in (
    'feedface', 'cefaedfe', 'feedfacf', 'cffaedfe',
    'cafebabe', 'bebafeca', 'cafebabf', 'bfbafeca',
)}
KEY_PARTS = ('skywalk', 'nehelper', 'neagent', 'nexus', 'vmnet',
             'networking.ethernet', 'networkextension', 'networking.networkextension')
OUT = Path('target/apple-path/system-entitlements-20260929')


def inspect(path):
    try:
        result = subprocess.run(
            ['/usr/bin/codesign', '-d', '--entitlements', ':-', path],
            capture_output=True, timeout=15,
        )
        if not result.stdout.strip():
            return None, 'unsigned-or-no-entitlements' if result.returncode else 'no-entitlements'
        try:
            entitlements = plistlib.loads(result.stdout)
        except Exception:
            return {'path': path, 'error': 'entitlements-not-parseable'}, 'error'
        selected = {k: v for k, v in entitlements.items()
                    if any(part in k.lower() for part in KEY_PARTS)}
        if selected:
            details = subprocess.run(
                ['/usr/bin/codesign', '-dv', path],
                capture_output=True, text=True, timeout=15,
            )
            verification = subprocess.run(
                ['/usr/bin/codesign', '--verify', '-R=anchor apple', path],
                capture_output=True, text=True, timeout=15,
            )
            return {
                'path': path, 'entitlements': selected,
                'signature_metadata': {
                    line.split('=', 1)[0]: line.split('=', 1)[1]
                    for line in details.stderr.splitlines()
                    if line.startswith(('Identifier=', 'TeamIdentifier=',
                                        'Platform identifier=', 'Signature='))
                },
                'apple_anchor_verified': verification.returncode == 0,
                'verification_error': verification.stderr.strip()
                if verification.returncode else None,
            }, 'matched'
        return None, 'other-entitlements'
    except subprocess.TimeoutExpired:
        return {'path': path, 'error': 'codesign-timeout'}, 'error'


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    errors, binaries, seen = [], [], set()
    visited = 0
    last = time.monotonic()
    for root in ROOTS:
        if not os.path.exists(root):
            continue
        for directory, dirs, files in os.walk(root, onerror=lambda e: errors.append(str(e))):
            # Cryptex mount aliases may be symlink directories. Walk their real
            # roots separately below, without following arbitrary nested links.
            for name in files:
                path = os.path.join(directory, name)
                try:
                    st = os.stat(path)
                    if not stat.S_ISREG(st.st_mode) or st.st_size < 4:
                        continue
                    identity = (st.st_dev, st.st_ino)
                    if identity in seen:
                        continue
                    seen.add(identity)
                    visited += 1
                    with open(path, 'rb') as f:
                        magic = f.read(4)
                    if magic in MAGICS:
                        binaries.append(path)
                except (OSError, PermissionError) as e:
                    errors.append(str(e))
                if time.monotonic() - last > 15:
                    print(f'discovery: {visited} files, {len(binaries)} Mach-O candidates', flush=True)
                    last = time.monotonic()
        print(f'root complete: {root}; {len(binaries)} candidates total', flush=True)
    (OUT / 'candidates.json').write_text(json.dumps(binaries, indent=2))
    (OUT / 'access-errors.json').write_text(json.dumps(errors, indent=2))
    matches, failures, counts = [], [], {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        for i, (row, status) in enumerate(pool.map(inspect, binaries), 1):
            counts[status] = counts.get(status, 0) + 1
            if row and status == 'matched':
                matches.append(row)
            elif row:
                failures.append(row)
            if i % 500 == 0:
                print(f'signatures: {i}/{len(binaries)}; matches {len(matches)}', flush=True)
    (OUT / 'matches.json').write_text(json.dumps(matches, indent=2))
    (OUT / 'inspection-errors.json').write_text(json.dumps(failures, indent=2))
    summary = {'roots': ROOTS, 'unique_files_examined': visited,
               'macho_candidates': len(binaries), 'signature_results': counts,
               'access_errors': len(errors), 'inspection_errors': len(failures),
               'limitations': 'Installed files only, default architecture selected by codesign; '
                              'does not establish runtime authorization or service accessibility.'}
    (OUT / 'summary.json').write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == '__main__':
    # Resolve the mounted cryptex roots explicitly; os.walk does not follow
    # their symlink aliases. Inode deduplication avoids duplicate inspections.
    for path in ('/System/Cryptexes/OS', '/System/Cryptexes/App',
                 '/System/Cryptexes/ExclaveOS', '/System/Cryptexes/Rosetta'):
        real = os.path.realpath(path)
        if real != path and os.path.isdir(real):
            ROOTS.append(real)
    main()
