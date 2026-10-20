"""Offline real C++ structural regression for D84/D85; no target code execution."""
from __future__ import annotations
import argparse
from dataclasses import asdict
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import types

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from src.ohscanner.contracts import ScanContext, ScanRequest
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.frontend import index_sources
from src.ohscanner.git_source import GitSource

VERSIONS = (
    ('before_compound', '6cbec8428a5c6c1ca86aa27b62ddc4ff2d06159f'),
    ('after_compound', 'e72855e970405bb8043cf4bb961207848c957a97'),
    ('integrated_after_string_receiver', '1e3b4c0cf02a1d5b0a817cc86dc746d28751b1e8'),
)


def git(git_dir, *args):
    env = os.environ.copy()
    env.update(GIT_NO_LAZY_FETCH='1', GIT_ALLOW_PROTOCOL='', GIT_TERMINAL_PROMPT='0')
    return subprocess.check_output(['git', '-c', 'remote.origin.promisor=false',
        '--git-dir', str(git_dir), *args], env=env, timeout=30, stderr=subprocess.PIPE)


def detector_at(commit):
    path = 'src/ohscanner/detectors/data/sensitive_exposure.py'
    source = subprocess.check_output(['git', '-C', str(ROOT), 'show', commit + ':' + path])
    name = 'src.ohscanner.detectors.data.t85_' + commit[:12]
    module = types.ModuleType(name)
    module.__package__ = name.rsplit('.', 1)[0]
    sys.modules[name] = module
    exec(compile(source, commit + ':' + path, 'exec'), module.__dict__)
    return module.SensitiveExposureDetector(), hashlib.sha256(source).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wifi-git-dir', type=Path, required=True)
    parser.add_argument('--cert-git-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--extra-detector-commit', action='append', default=[],
                        help='Optional fixed development commit for the same real-source replay')
    args = parser.parse_args()
    runtime_changes = subprocess.check_output(['git', '-C', str(ROOT), 'diff',
        VERSIONS[-1][1], '--', 'src/ohscanner', ':!src/ohscanner/detectors/data/sensitive_exposure.py'])
    if runtime_changes:
        raise ValueError('shared scanner runtime differs from frozen integrated target')
    manifest = json.loads((ROOT / 'research/data_sensitive/T85_SOURCE_MANIFEST.json').read_text())
    stores = {'wifi': args.wifi_git_dir, 'cert': args.cert_git_dir}
    detector_rows = []
    for label, commit in (*VERSIONS, *(('followup', ref) for ref in args.extra_detector_commit)):
        detector, digest = detector_at(commit)
        detector_rows.append({'label': label, 'commit': commit, 'detector': detector,
                              'implementation_sha256': digest})
    studies = []
    for component in manifest['components']:
        store, commit = stores[component['key']], component['commit']
        actual_tree = git(store, 'rev-parse', commit + '^{tree}').decode().strip()
        if actual_tree != component['tree']:
            raise ValueError('tree drift: ' + component['key'])
        sources, checked, structures = [], [], []
        for row in component['files']:
            path = row['path']
            data = git(store, 'cat-file', 'blob', commit + ':' + path)
            blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
            tree_blob = git(store, 'rev-parse', commit + ':' + path).decode().strip()
            if blob != tree_blob or blob != row['blob'] or len(data) != row['bytes'] \
                    or hashlib.sha256(data).hexdigest() != row['sha256']:
                raise ValueError('source byte/blob drift: ' + path)
            sources.append(GitSource(path, 'cpp', blob, data))
            checked.append({**row, 'commit_tree_blob_verified': True})
            lines = data.decode('utf-8').splitlines()
            structures.append({'path': path, 'compound_assignment_lines': [i+1 for i,line in enumerate(lines)
                if re.search(r'(?:\+=|\^=|\|=|&=|-=|\*=|/=)', line)],
                'c_str_lines': [i+1 for i,line in enumerate(lines) if '.c_str()' in line],
                'explicit_std_string_lines': [i+1 for i,line in enumerate(lines) if 'std::string' in line]})
        units, ast, _ = index_sources(tuple(sources))
        units = tuple(sorted(units, key=lambda u: u.path))
        repository = component['repository']
        request = ScanRequest('t85-real-cpp-' + component['key'], repository, commit,
            snapshot_digest(units), 'current-component:' + repository,
            profile_id='light-ast', provenance='git_object')
        runs = []
        for version in detector_rows:
            run = version['detector'].detect(ScanContext(request, units, {'ast': ast}), units)
            runs.append({**{k: v for k,v in version.items() if k != 'detector'},
                         'version': run.version, 'candidate_count': len(run.findings), 'run': asdict(run)})
        studies.append({'key': component['key'], 'repository': repository, 'commit': commit,
            'tree': component['tree'], 'files': checked, 'structures': structures,
            'parse_status': {u.path: u.parse_status for u in units},
            'snapshot_sha256': request.snapshot_sha256, 'runs': runs})
    differences = []
    for study in studies:
        before = study['runs'][0]['run']
        after = study['runs'][-1]['run']
        def by_site(run):
            return {(f['file'], f['line'], f['rule_id'], f['symbol']): f for f in run['findings']}
        old, new = by_site(before), by_site(after)
        differences.append({'component': study['key'],
            'added_sites': [list(key) for key in sorted(new.keys() - old.keys())],
            'removed_sites': [list(key) for key in sorted(old.keys() - new.keys())],
            'changed_evidence_sites': [list(key) for key in sorted(new.keys() & old.keys()) if old[key] != new[key]],
            'file_coverage_unchanged': before['file_outcomes'] == after['file_outcomes']})
    result = {'schema': 1, 'study': 'T85 fixed real C++ structure regression',
        'network': 'disabled for Git; existing local commit/tree/blob objects only',
        'source_policy': 'Unmodified complete selected files; default production detector profile dispatch, '
            'including unknown-profile name heuristics. No synthetic source injection or extra sink model.',
        'studies': studies, 'differences': differences,
        'shared_runtime': {'target': VERSIONS[-1][1], 'tracked_src_matches_target_except_detector': True,
            'python': sys.version, 'parsers': {name: importlib.metadata.version(name) for name in
                ('tree-sitter', 'tree-sitter-c', 'tree-sitter-cpp')}},
        'interpretation': 'Unlabelled compatibility/behavior comparisons only; candidate count is not accuracy. '
            'No target build/runtime execution or product vulnerability claim.'}
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print(json.dumps([{'component': s['key'], 'counts': [r['candidate_count'] for r in s['runs']],
        'versions': [r['version'] for r in s['runs']], 'status': [r['run']['status'] for r in s['runs']]}
        for s in studies]))


if __name__ == '__main__':
    main()
