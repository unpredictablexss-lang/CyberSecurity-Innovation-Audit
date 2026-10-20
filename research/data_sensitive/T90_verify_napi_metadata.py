"""Independent NAPI metadata roles and explicitly unbound cross-repository replay."""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
BEFORE = 'ef7cb1c2abc8cdab6b13c3db92bd7c985ceb00cb'


def git(git_dir, *args):
    env = os.environ.copy()
    env.update(GIT_NO_LAZY_FETCH='1', GIT_ALLOW_PROTOCOL='', GIT_TERMINAL_PROMPT='0')
    return subprocess.check_output(['git', '-c', 'remote.origin.promisor=false',
        '--git-dir', str(git_dir), *args], env=env, timeout=30, stderr=subprocess.PIPE)


def child(args):
    sys.path.insert(0, str(args.snapshot_root))
    sys.path.insert(1, str(ROOT))  # Load independent test helpers after the fixed src snapshot.
    from dataclasses import asdict
    from src.ohscanner.contracts import ScanContext, ScanRequest
    from src.ohscanner.detectors.data.sensitive_exposure import SensitiveExposureDetector
    from src.ohscanner.fixture import snapshot_digest
    from src.ohscanner.frontend import index_sources
    from src.ohscanner.git_source import GitSource
    from src.ohscanner.runner import DetectorRegistry, run_all_with_coverage

    spec = importlib.util.spec_from_file_location('t90_independent_snapshot_tests',
        ROOT / 'tests/detectors/data/test_t90_napi_metadata_roles.py')
    tests_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tests_module)
    log = io.StringIO()
    tests = unittest.TextTestRunner(stream=log, verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromModule(tests_module))
    manifest = json.loads((ROOT / 'research/data_sensitive/T85_SOURCE_MANIFEST.json').read_text())
    cert = next(component for component in manifest['components'] if component['key'] == 'cert')
    if git(args.cert_git_dir, 'rev-parse', cert['commit'] + '^{tree}').decode().strip() != cert['tree']:
        raise ValueError('fixed commit/tree mismatch')
    expected = {row['path']: row for row in cert['files']}
    sources, rows = [], []
    for path in expected:
        data = git(args.cert_git_dir, 'cat-file', 'blob', cert['commit'] + ':' + path)
        blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        if blob != git(args.cert_git_dir, 'rev-parse', cert['commit'] + ':' + path).decode().strip():
            raise ValueError('blob mismatch: ' + path)
        row = {'path': path, 'blob': blob, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
        if path in expected and row != expected[path]:
            raise ValueError('T85 source drift: ' + path)
        sources.append(GitSource(path, 'c' if path.endswith('.c') else 'cpp', blob, data))
        rows.append(row)
    api_manifest = json.loads((ROOT / 'research/data_sensitive/T90_API_SOURCE_MANIFEST.json').read_text())
    for row in api_manifest['dependency_evidence']:
        data = git(args.cert_git_dir, 'cat-file', 'blob', row['commit'] + ':' + row['path'])
        if len(data) != row['bytes'] or hashlib.sha256(data).hexdigest() != row['sha256'] \
                or git(args.cert_git_dir, 'rev-parse', row['commit'] + ':' + row['path']).decode().strip() != row['blob']:
            raise ValueError('dependency evidence changed')
    external = []
    for row in api_manifest['files']:
        is_node = row['repository'] == 'openharmony/third_party_node'
        git_dir = args.node_git_dir if is_node else args.napi_git_dir
        if git(git_dir, 'rev-parse', row['commit'] + '^{tree}').decode().strip() != row['tree']:
            raise ValueError('external tree mismatch')
        data = git(git_dir, 'cat-file', 'blob', row['commit'] + ':' + row['path'])
        if git(git_dir, 'rev-parse', row['commit'] + ':' + row['path']).decode().strip() != row['blob'] \
                or hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() != row['blob'] \
                or len(data) != row['bytes'] or hashlib.sha256(data).hexdigest() != row['sha256']:
            raise ValueError('external source drift: ' + row['path'])
        path = ('third_party/node/' if is_node else 'foundation/arkui/napi/') + row['path']
        sources.append(GitSource(path, 'cpp', row['blob'], data))
        rows.append({'path': path, 'blob': row['blob'], 'bytes': row['bytes'], 'sha256': row['sha256']})
        external.append({**row, 'indexed_path': path})

    def execute(context, detector):
        direct = detector.detect(context, context.units)
        registry = DetectorRegistry()
        registry.register(detector)
        reports, coverage = run_all_with_coverage(context, registry)
        return {'direct': asdict(direct), 'runner': reports[0].to_dict(), 'coverage': coverage}

    scopes = []
    for scope, selected in (('strict-T85-three-files', sources[:3]),
                            ('unbound-multi-repository-nine-file-collection', sources)):
        units, ast, _ = index_sources(tuple(selected))
        units = tuple(sorted(units, key=lambda unit: unit.path))
        composite = len(selected) != 3
        repository = 'fixture/t90-collection' if composite else cert['repository']
        request = ScanRequest('t90-' + scope, repository,
            'unbound-multiple-git-origins' if composite else cert['commit'], snapshot_digest(units),
            'current-component:' + repository, profile_id='m0-synthetic' if composite else 'light-ast',
            provenance='fixture' if composite else 'git_object')
        ctx = ScanContext(request, units, {'ast': ast})
        facts = {}
        for unit in units:
            data = unit.text.encode()
            row = next(row for row in rows if row['path'] == unit.path)
            if hashlib.sha256(data).hexdigest() != row['sha256'] or len(data) != row['bytes']:
                raise ValueError('raw bytes changed: ' + unit.path)
            calls = []
            for call in ast[unit.path]['calls']:
                start, end = call['start_byte'], call['end_byte']
                if not (0 <= start < end <= len(data)) or data[:start].count(b'\n') + 1 != call['line']:
                    raise ValueError('original call offset drift: ' + unit.path)
                calls.append({**call, 'original_span_sha256': hashlib.sha256(data[start:end]).hexdigest()})
            facts[unit.path] = calls
        scopes.append({'scope': scope, 'selected_paths': [unit.path for unit in units],
            'collection_is_not_a_build_or_linkage_claim': composite,
            'snapshot_sha256': request.snapshot_sha256,
            'parse_status': {unit.path: unit.parse_status for unit in units},
            'calls': facts, **execute(ctx, SensitiveExposureDetector())})

    tester = tests_module.t89.T89CleanupBindingTests()
    cases = [
        ('complete-invented-pure-metadata-body', tests_module.TYPES + tests_module.PURE +
            'void Callback(napi_value key,napi_env env){napi_valuetype kind;'
            'auto status=napi_typeof(env,key,&kind);HILOG_INFO(1,"%{public}d %{public}d",status,kind);}', 0),
        ('unbound-name-status-log', tests_module.TYPES +
            'void Callback(napi_value key,napi_env env){napi_valuetype kind;'
            'auto status=napi_typeof(env,key,&kind);HILOG_INFO(1,"%{public}d",status);}', 1),
        ('unbound-actual-byte-getter', tests_module.TYPES +
            'void Callback(napi_value key,napi_env env){char buffer[32];size_t length;'
            'napi_get_value_string_utf8(env,key,buffer,sizeof(buffer),&length);}', 1),
        ('same-name-secret-return-body', 'const char *napi_typeof(int env,const char *value,int *out){return value;}'
            'void Callback(const char *key){int out;auto status=napi_typeof(0,key,&out);HILOG_INFO(1,"%{public}s",status);}', 1),
    ]
    observations = []
    for name, source, expected_after in cases:
        ctx = tester.context(source)
        observations.append({'case': name, 'source': source,
            'source_role': 'Explicit synthetic Callback argument 0',
            'expected_after_has_candidate': bool(expected_after),
            'parse_status': {unit.path: unit.parse_status for unit in ctx.units},
            **execute(ctx, SensitiveExposureDetector(tests_module.t89.MODEL))})
    result = {'revision': args.revision, 'version': SensitiveExposureDetector.version,
        'tests': {'count': tests.testsRun, 'failures': len(tests.failures), 'errors': len(tests.errors), 'log': log.getvalue()},
        'source': {'repository': cert['repository'], 'commit': cert['commit'], 'tree': cert['tree'], 'files': rows[:3]},
        'external_source_origins': external,
        'dependency_evidence': api_manifest['dependency_evidence'],
        'binding_assessment': api_manifest['binding_assessment'],
        'reviewed_api_roles': api_manifest['reviewed_api_roles'],
        'scopes': scopes, 'role_cases': observations,
        'implementation_sha256': {path: hashlib.sha256((args.snapshot_root / path).read_bytes()).hexdigest()
            for path in ('src/ohscanner/detectors/data/sensitive_exposure.py', 'src/ohscanner/detectors/data/models.py')}}
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--after-commit')
    parser.add_argument('--cert-git-dir', type=Path, required=True)
    parser.add_argument('--napi-git-dir', type=Path, required=True)
    parser.add_argument('--node-git-dir', type=Path, required=True)
    parser.add_argument('--cache', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--snapshot-root', type=Path)
    parser.add_argument('--revision')
    parser.add_argument('--allow-failing-after', action='store_true')
    args = parser.parse_args()
    if args.snapshot_root:
        child(args)
        return
    if not args.after_commit or not args.cache:
        parser.error('--after-commit and --cache required')
    args.cache.mkdir(parents=True, exist_ok=True)
    runs = []
    for revision in (BEFORE, args.after_commit):
        if len(revision) != 40 or subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', revision]).decode().strip() != revision:
            raise ValueError('full fixed commit SHA required')
        archive = subprocess.check_output(['git', '-C', str(ROOT), 'archive', revision, 'src/'])
        destination = Path(tempfile.mkdtemp(prefix='t90_' + revision[:10] + '_', dir=args.cache.resolve()))
        with tarfile.open(fileobj=io.BytesIO(archive)) as bundle:
            bundle.extractall(destination, filter='data')
        output = destination / 'probe.json'
        subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), '--snapshot-root', str(destination),
             '--revision', revision, '--cert-git-dir', str(args.cert_git_dir),
             '--napi-git-dir', str(args.napi_git_dir), '--node-git-dir', str(args.node_git_dir),
             '--output', str(output)], check=True, timeout=120)
        row = json.loads(output.read_text(encoding='utf-8'))
        row['src_archive_sha256'] = hashlib.sha256(archive).hexdigest()
        row['src_tree_oid'] = subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', revision + ':src']).decode().strip()
        runs.append(row)
    differences = []
    def changed_paths(old, new, prefix=''):
        if isinstance(old, dict) and isinstance(new, dict):
            return [path for key in sorted(old.keys() | new.keys())
                    for path in (changed_paths(old[key], new[key], prefix + '/' + key)
                                 if key in old and key in new else [prefix + '/' + key])]
        if isinstance(old, list) and isinstance(new, list) and len(old) == len(new):
            return [path for index, (a, b) in enumerate(zip(old, new))
                    for path in changed_paths(a, b, prefix + '/' + str(index))]
        return [prefix] if old != new else []
    for before, after in zip(runs[0]['scopes'], runs[1]['scopes']):
        sites = lambda row: {(d['file'], d['line'], d['rule_id']): d for d in row['runner']['diagnostics']}
        old, new = sites(before), sites(after)
        direct_sites = lambda row: {(d['file'], d['line'], d['rule_id'], d.get('symbol')): d
                                    for d in row['direct']['findings']}
        old_direct, new_direct = direct_sites(before), direct_sites(after)
        differences.append({'scope': before['scope'],
            'direct_added_sites': sorted(new_direct.keys() - old_direct.keys()),
            'direct_removed_sites': sorted(old_direct.keys() - new_direct.keys()),
            'direct_changed_findings': sorted(key for key in old_direct.keys() & new_direct.keys()
                                             if old_direct[key] != new_direct[key]),
            'runner_added_sites': sorted(new.keys() - old.keys()),
            'runner_removed_sites': sorted(old.keys() - new.keys()),
            'runner_changed_messages': sorted(key for key in old.keys() & new.keys() if old[key]['message'] != new[key]['message']),
            'legacy_ids_unchanged_for_common_sites': all(old[key]['diagnostic_id'] == new[key]['diagnostic_id'] for key in old.keys() & new.keys()),
            'occurrence_identity': 'unknown; null IDs do not establish stability',
            'runner_coverage_unchanged': before['coverage'] == after['coverage'],
            'runner_coverage_changed_paths': changed_paths(before['coverage'], after['coverage']),
            'raw_call_facts_unchanged': before['calls'] == after['calls']})
    result = {'study': 'T90 independent metadata roles and unresolved NAPI binding', 'runs': runs,
        'src_tree_identical': runs[0]['src_tree_oid'] == runs[1]['src_tree_oid'],
        'differences': differences, 'interpretation': 'Same-scope and added-definition scopes are separate experiments; '
        'candidate changes are not accuracy or product impact. No target source executed.'}
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'tests': [{k: v for k, v in run['tests'].items() if k != 'log'} for run in runs],
        'versions': [run['version'] for run in runs],
        'scopes': [[{'scope': scope['scope'], 'direct': len(scope['direct']['findings']),
                    'runner': len(scope['runner']['diagnostics']), 'parse': scope['parse_status']}
                   for scope in run['scopes']] for run in runs]}, ensure_ascii=False))
    if not args.allow_failing_after and (runs[1]['tests']['failures'] or runs[1]['tests']['errors']):
        raise SystemExit(1)
    if not args.allow_failing_after:
        for case in runs[1]['role_cases']:
            for count in (len(case['direct']['findings']), len(case['runner']['diagnostics'])):
                if bool(count) != case['expected_after_has_candidate']:
                    raise ValueError('role expectation failed: ' + case['case'])


if __name__ == '__main__':
    main()
