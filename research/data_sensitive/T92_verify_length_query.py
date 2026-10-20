"""T92 independent length-query roles, provenance and fixed certificate replay.

Each scanner revision runs from its own Git-archived src snapshot in a fresh Python
process. Target source is read from pinned local Git objects; no source is executed.
"""
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
BEFORE = '0420a3905b1558e1d1251ac11e5e2034e6c3e45d'
OWNER = BEFORE


def git(git_dir, *args):
    env = os.environ.copy()
    env.update(GIT_NO_LAZY_FETCH='1', GIT_ALLOW_PROTOCOL='', GIT_TERMINAL_PROMPT='0')
    return subprocess.check_output(['git', '-c', 'remote.origin.promisor=false',
        '--git-dir', str(git_dir), *args], env=env, timeout=30, stderr=subprocess.PIPE)


def child(args):
    sys.path.insert(0, str(args.snapshot_root))
    sys.path.insert(1, str(ROOT))
    from dataclasses import asdict
    from src.ohscanner.contracts import ScanContext, ScanRequest
    from src.ohscanner.detectors.data.models import SensitiveSourceModel
    from src.ohscanner.detectors.data.sensitive_exposure import LocalFlow, SensitiveExposureDetector
    from src.ohscanner.fixture import snapshot_digest
    from src.ohscanner.frontend import index_sources
    from src.ohscanner.git_source import GitSource
    from src.ohscanner.runner import DetectorRegistry, run_all_with_coverage
    from src.parser import syntax_normalize

    spec = importlib.util.spec_from_file_location('t92_independent_snapshot_tests',
        ROOT / 'tests/detectors/data/test_t92_length_query_roles.py')
    tests_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tests_module)
    log = io.StringIO()
    tests = unittest.TextTestRunner(stream=log, verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromModule(tests_module))
    manifest = json.loads((ROOT / 'research/data_sensitive/T85_SOURCE_MANIFEST.json').read_text())
    cert = next(component for component in manifest['components'] if component['key'] == 'cert')
    actual_tree = git(args.cert_git_dir, 'rev-parse', cert['commit'] + '^{tree}').decode().strip()
    if actual_tree != cert['tree']:
        raise ValueError('fixed target commit/tree mismatch')
    roles = json.loads((ROOT / 'research/data_sensitive/T92_LENGTH_SOURCE_MANIFEST.json').read_text())
    for row in roles['files'] + roles['dependency_evidence'] + roles['include_context']:
        git_dir = {'openharmony/security_certificate_framework': args.cert_git_dir,
            'openharmony/arkui_napi': args.napi_git_dir,
            'openharmony/third_party_node': args.node_git_dir}[row['repository']]
        data = git(git_dir, 'cat-file', 'blob', row['commit'] + ':' + row['path'])
        if git(git_dir, 'rev-parse', row['commit'] + '^{tree}').decode().strip() != row['tree'] \
                or git(git_dir, 'rev-parse', row['commit'] + ':' + row['path']).decode().strip() != row['blob'] \
                or hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() != row['blob'] \
                or len(data) != row['bytes'] or hashlib.sha256(data).hexdigest() != row['sha256']:
            raise ValueError('research provenance drift: ' + row['path'])
    sources, rows = [], []
    for row in cert['files']:
        data = git(args.cert_git_dir, 'cat-file', 'blob', cert['commit'] + ':' + row['path'])
        blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        tree_blob = git(args.cert_git_dir, 'rev-parse', cert['commit'] + ':' + row['path']).decode().strip()
        if blob != tree_blob or blob != row['blob'] or len(data) != row['bytes'] \
                or hashlib.sha256(data).hexdigest() != row['sha256']:
            raise ValueError('target byte/blob drift: ' + row['path'])
        sources.append(GitSource(row['path'], 'cpp', blob, data))
        rows.append({**row, 'commit_tree_blob_verified': True})
    units, ast, _ = index_sources(tuple(sources))
    units = tuple(sorted(units, key=lambda unit: unit.path))
    request = ScanRequest('t92-fixed-certificate', cert['repository'], cert['commit'], snapshot_digest(units),
        'current-component:' + cert['repository'], profile_id='light-ast', provenance='git_object')
    ctx = ScanContext(request, units, {'ast': ast})
    detector = SensitiveExposureDetector()
    direct = detector.detect(ctx, units)
    registry = DetectorRegistry()
    registry.register(detector)
    reports, sidecar = run_all_with_coverage(ctx, registry)
    cases = []
    tester = tests_module.t89.T89CleanupBindingTests()
    query = 'auto status=napi_get_value_string_utf8(0,key,nullptr,0,&length);'
    status_log = 'HILOG_INFO(1,"%{public}d",status);'
    byte_getter = 'napi_get_value_string_utf8(env,key,buffer,sizeof(buffer),&length);'
    definitions = [
        ('visible-length-body-metadata-log', tests_module.LENGTH_BODY +
            'void Callback(const char *key){unsigned length=0;\n' + query + '\n' + status_log + '\n}', status_log, 0),
        ('unbound-query', 'void Callback(const char *key){unsigned length=0;\n' + query + '\n}', query, 1),
        ('unbound-byte-getter', tests_module.TYPES + 'void Callback(napi_value key,napi_env env){size_t length=0;char buffer[32];\n' + byte_getter + '\n}', byte_getter, 1),
        ('custom-secret-return', 'const char *napi_get_value_string_utf8(int env,const char *value,char *buf,unsigned size,unsigned *out){return value;}\n'
            'void Callback(const char *key){unsigned length=0;\n' + query + '\nHILOG_INFO(1,"%{public}s",status);\n}', 'HILOG_INFO(1,"%{public}s",status);', 1),
    ]
    for name, source, statement, expected in definitions:
        fixture_ctx = tester.context(source)
        fixture_detector = SensitiveExposureDetector(tests_module.t89.MODEL)
        case_direct = fixture_detector.detect(fixture_ctx, fixture_ctx.units)
        case_registry = DetectorRegistry()
        case_registry.register(fixture_detector)
        case_reports, case_coverage = run_all_with_coverage(fixture_ctx, case_registry)
        line = source.splitlines().index(statement) + 1
        select = lambda findings: [finding for finding in findings
                                   if finding.file == 'service.cpp' and finding.line == line]
        direct_target = select(case_direct.findings)
        runner_target = select(case_reports[0].diagnostics)
        cases.append({'case': name, 'source': source, 'buffer_argument_index': 2,
            'capacity_argument_index': 3, 'length_output_argument_index': 4, 'target_statement': statement,
            'expected_after_target_candidates': expected,
            'direct_target_candidates': [asdict(finding) for finding in direct_target],
            'runner_target_diagnostics': [finding.to_dict() for finding in runner_target],
            'call_facts': [call for call in fixture_ctx.shared_facts['ast']['service.cpp']['calls'] if call['line'] == line],
            'direct_status': case_direct.status, 'direct_file_outcomes': case_direct.file_outcomes,
            'runner_status': case_reports[0].status, 'runner_coverage': case_coverage})
    private, call_positions, projections = {}, {}, {}
    expected = {row['path']: row for row in rows}
    for unit in units:
        data = unit.text.encode()
        if unit.sha256 != expected[unit.path]['sha256'] \
                or hashlib.sha256(data).hexdigest() != expected[unit.path]['sha256']:
            raise ValueError('indexed raw source changed: ' + unit.path)
        normalize = getattr(syntax_normalize, 'normalize_empty_cpp_linkage_wrappers', lambda value: value)
        projected = normalize(data)
        breaks = lambda value: [i for i,byte in enumerate(value) if byte in (10, 13)]
        if len(projected) != len(data) or breaks(data) != breaks(projected):
            raise ValueError('projection byte/line-break drift: ' + unit.path)
        projections[unit.path] = {'original_bytes': len(data), 'projected_bytes': len(projected),
            'projected_sha256': hashlib.sha256(projected).hexdigest(),
            'changed_offsets': [i for i,(old,new) in enumerate(zip(data,projected)) if old != new],
            'line_break_offsets_unchanged': True}
        flow = LocalFlow(unit, SensitiveSourceModel('fixture/t92', 'a' * 40))
        if flow.b != data:
            raise ValueError('private flow raw source changed: ' + unit.path)
        private[unit.path] = {'root_has_error': flow.tree.root_node.has_error,
            'root_end_byte': flow.tree.root_node.end_byte,
            'raw_source_sha256': hashlib.sha256(flow.b).hexdigest()}
        calls = []
        for call in ast[unit.path]['calls']:
            start, end = call['start_byte'], call['end_byte']
            if not (0 <= start < end <= len(data)) or data[:start].count(b'\n') + 1 != call['line']:
                raise ValueError('original byte/line mapping drift: ' + unit.path)
            calls.append({**call, 'original_span_sha256': hashlib.sha256(data[start:end]).hexdigest()})
        call_positions[unit.path] = calls
    result = {'revision': args.revision, 'version': detector.version,
        'tests': {'count': tests.testsRun, 'failures': len(tests.failures), 'errors': len(tests.errors), 'log': log.getvalue()},
        'source': {**cert, 'files': rows}, 'research_provenance': roles,
        'snapshot_sha256': request.snapshot_sha256,
        'parse_status': {unit.path: unit.parse_status for unit in units},
        'private_ast': private, 'call_positions': call_positions, 'parse_projections': projections,
        'direct': asdict(direct), 'runner': reports[0].to_dict(), 'coverage': sidecar,
        'independent_role_cases': cases,
        'implementation_sha256': {path: hashlib.sha256((args.snapshot_root / path).read_bytes()).hexdigest()
            if (args.snapshot_root / path).is_file() else None
            for path in ('src/parser/ast.py', 'src/parser/syntax_normalize.py',
                         'src/ohscanner/detectors/data/sensitive_exposure.py',
                         'src/ohscanner/detectors/data/property_keys.py',
                         'src/ohscanner/detectors/data/log_macro_roles.py')}}
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')


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
    args = parser.parse_args()
    if args.snapshot_root:
        child(args)
        return
    if not args.after_commit or not args.cache:
        parser.error('--after-commit and --cache required')
    args.cache.mkdir(parents=True, exist_ok=True)
    runs = []
    for revision in (BEFORE, args.after_commit):
        actual = subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', revision]).decode().strip()
        if actual != revision or len(actual) != 40:
            raise ValueError('fixed full commit SHA required')
        archive = subprocess.check_output(['git', '-C', str(ROOT), 'archive', revision, 'src/'])
        destination = Path(tempfile.mkdtemp(prefix='t92_' + revision[:10] + '_', dir=args.cache.resolve()))
        with tarfile.open(fileobj=io.BytesIO(archive)) as bundle:
            bundle.extractall(destination, filter='data')
        output = destination / 'probe.json'
        subprocess.run([sys.executable, str(Path(__file__).resolve()), '--snapshot-root', str(destination),
            '--revision', revision, '--cert-git-dir', str(args.cert_git_dir),
            '--napi-git-dir', str(args.napi_git_dir), '--node-git-dir', str(args.node_git_dir), '--output', str(output)],
            check=True, timeout=120)
        row = json.loads(output.read_text(encoding='utf-8'))
        row['src_archive_sha256'] = hashlib.sha256(archive).hexdigest()
        row['src_tree_oid'] = subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', revision + ':src']).decode().strip()
        runs.append(row)
    before, after = runs
    def sites(run):
        return {(f['file'], f['line'], f['rule_id'], f['symbol']): f for f in run['direct']['findings']}
    old, new = sites(before), sites(after)
    old_diag = {(d['file'], d['line'], d['rule_id']): d for d in before['runner']['diagnostics']}
    new_diag = {(d['file'], d['line'], d['rule_id']): d for d in after['runner']['diagnostics']}
    identities = [{'site': list(key), 'diagnostic_id_before': old_diag[key]['diagnostic_id'],
        'diagnostic_id_after': new_diag[key]['diagnostic_id'],
        'occurrence_id_before': old_diag[key].get('occurrence_id'),
        'occurrence_id_after': new_diag[key].get('occurrence_id')}
        for key in sorted(old_diag.keys() & new_diag.keys())]
    result = {'schema': 1, 'study': 'T92 independent length-query metadata/material roles',
        'src_tree_identical': before['src_tree_oid'] == after['src_tree_oid'],
        'owner_baseline': OWNER, 'runs': runs,
        'difference': {'direct_added_sites': [list(key) for key in sorted(new.keys() - old.keys())],
            'direct_removed_sites': [list(key) for key in sorted(old.keys() - new.keys())],
            'direct_changed_evidence_sites': [list(key) for key in sorted(new.keys() & old.keys()) if old[key] != new[key]],
            'runner_added_sites': [list(key) for key in sorted(new_diag.keys() - old_diag.keys())],
            'runner_removed_sites': [list(key) for key in sorted(old_diag.keys() - new_diag.keys())],
            'runner_changed_messages': [list(key) for key in sorted(old_diag.keys() & new_diag.keys())
                                        if old_diag[key]['message'] != new_diag[key]['message']],
            'same_site_runner_identities': identities,
            'coverage_identical': before['coverage'] == after['coverage'],
            'all_original_call_positions_unchanged': before['call_positions'] == after['call_positions']},
        'interpretation': 'Length-query metadata/material role compatibility only; direct invocation and '
            'Runner are reported separately. No full coverage, product impact or accuracy claim.'}
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print(json.dumps({'tests': [{k:v for k,v in run['tests'].items() if k != 'log'} for run in runs],
        'versions': [run['version'] for run in runs],
        'direct_counts': [len(run['direct']['findings']) for run in runs],
        'runner_counts': [len(run['runner']['diagnostics']) for run in runs],
        'positions_unchanged': result['difference']['all_original_call_positions_unchanged']}))
    if after['tests']['failures'] or after['tests']['errors']:
        raise SystemExit(1)
    for case in after['independent_role_cases']:
        for field in ('direct_target_candidates', 'runner_target_diagnostics'):
            if bool(case[field]) != bool(case['expected_after_target_candidates']):
                raise ValueError('role case lost material or retained schema key: ' + case['case'])


if __name__ == '__main__':
    main()
