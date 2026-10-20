"""Replay five pinned DSoftBus blobs offline; retain candidate and coverage uncertainty.

Requires local commit/tree objects. Missing source bytes may be retrieved only with --fetch.
Never checks out or executes target code; every byte is checked against the pinned tree.
"""
from __future__ import annotations
import argparse
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from src.ohscanner.contracts import ScanContext, ScanRequest
from src.ohscanner.detectors.data.sensitive_exposure import SensitiveExposureDetector
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.frontend import index_sources
from src.ohscanner.git_source import GitSource


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--git-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cache', type=Path)
    parser.add_argument('--fetch', action='store_true')
    args = parser.parse_args()
    def git(*argv):
        environment = os.environ.copy()
        environment.update(GIT_NO_LAZY_FETCH='1', GIT_ALLOW_PROTOCOL='', GIT_TERMINAL_PROMPT='0')
        return subprocess.check_output(['git', '-c', 'remote.origin.promisor=false',
            '--git-dir', str(args.git_dir), *argv], timeout=30, env=environment,
            stderr=subprocess.PIPE)
    baseline = json.loads((ROOT / 'research/data_sensitive/D45_DSOFTBUS_CURRENT_PROFILE.json').read_text())
    repository, commit, tree = (baseline[key] for key in ('repository', 'commit', 'tree'))
    actual_tree = git('rev-parse', commit + '^{tree}').decode().strip()
    if actual_tree != tree:
        raise ValueError('pinned commit/tree mismatch')
    sources, rows = [], []
    for expected in baseline['files']:
        path = expected['path']
        cache = args.cache / path if args.cache else None
        if cache and cache.is_file():
            data = cache.read_bytes()
        elif args.fetch and cache:
            url = f'https://raw.githubusercontent.com/{repository}/{commit}/{path}'
            with urlopen(Request(url, headers={'User-Agent': 'OHScanner-T83'}), timeout=30) as response:
                data = response.read()
            cache.parent.mkdir(parents=True, exist_ok=True)
            cache.write_bytes(data)
        else:
            data = git('cat-file', 'blob', commit + ':' + path)
        sha256 = hashlib.sha256(data).hexdigest()
        blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        tree_blob = git('rev-parse', commit + ':' + path).decode().strip()
        if len(data) != expected['size'] or sha256 != expected['sha256']:
            raise ValueError('pinned source byte drift: ' + path)
        if blob != expected['blob'] or blob != tree_blob:
            raise ValueError('pinned blob/tree drift: ' + path)
        rows.append({**expected, 'commit_tree_blob_verified': True})
        sources.append(GitSource(path, 'c' if path.endswith('.c') else 'cpp', blob, data))
    units, ast, _ = index_sources(tuple(sources))
    units = tuple(sorted(units, key=lambda unit: unit.path))
    request = ScanRequest('t83-real-dsoftbus', repository, commit, snapshot_digest(units),
                          'current-component:' + repository, profile_id='light-ast', provenance='git_object')
    detector = SensitiveExposureDetector()
    run = detector.detect(ScanContext(request, units, {'ast': ast}), units)
    implementation = ROOT / 'src/ohscanner/detectors/data/sensitive_exposure.py'
    result = {
        'schema': 1, 'study': 'T83 exact-source compatibility replay',
        'repository': repository, 'commit': commit, 'tree': tree,
        'source_manifest': 'research/data_sensitive/D45_DSOFTBUS_CURRENT_PROFILE.json',
        'source_files': rows, 'snapshot_sha256': request.snapshot_sha256,
        'detector_version': detector.version,
        'detector_implementation_sha256': hashlib.sha256(implementation.read_bytes()).hexdigest(),
        'parse_status': {unit.path: unit.parse_status for unit in units},
        'candidate_count': len(run.findings), 'run': asdict(run),
        'network': 'explicit pinned raw-source fetch allowed' if args.fetch else 'none; cached bytes/local Git objects',
        'interpretation': 'Source-bound static candidates only; 5-file scope, incomplete coverage retained. '
                          'Development compatibility inputs are not independent labels; no accuracy claim, '
                          'runtime execution, unauthorized-reader evidence or product impact is established.',
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'output': str(args.output), 'version': detector.version,
                      'candidates': len(run.findings), 'status': run.status,
                      'files': len(units), 'file_outcomes': run.file_outcomes}))


if __name__ == '__main__':
    main()
