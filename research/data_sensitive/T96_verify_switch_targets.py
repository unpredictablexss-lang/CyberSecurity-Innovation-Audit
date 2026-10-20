"""T96 independent C++ switch target joins replay.

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
BEFORE = '73b9a761eb06b11a383793e24ccc6a01b2e4c440'
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

    spec = importlib.util.spec_from_file_location('t96_independent_snapshot_tests',
        ROOT / 'tests/detectors/data/test_t96_switch_target_joins.py')
    tests_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tests_module)
    test_log = io.StringIO()
    tests = unittest.TextTestRunner(stream=test_log, verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromModule(tests_module))
    manifest = json.loads((ROOT / 'research/data_sensitive/T85_SOURCE_MANIFEST.json').read_text())
    cert = next(component for component in manifest['components'] if component['key'] == 'cert')
    actual_tree = git(args.cert_git_dir, 'rev-parse', cert['commit'] + '^{tree}').decode().strip()
    if actual_tree != cert['tree']:
        raise ValueError('fixed target commit/tree mismatch')
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
    request = ScanRequest('t96-fixed-certificate', cert['repository'], cert['commit'], snapshot_digest(units),
        'current-component:' + cert['repository'], profile_id='light-ast', provenance='git_object')
    ctx = ScanContext(request, units, {'ast': ast})
    detector = SensitiveExposureDetector()
    direct = detector.detect(ctx, units)
    registry = DetectorRegistry()
    registry.register(detector)
    reports, sidecar = run_all_with_coverage(ctx, registry)
    cases = []
    tester = tests_module.T96SwitchTargetTests()
    definitions = tests_module.fixtures()
    partial_source=tests_module.build('case 0:p=&second;break;default:p=&second;break;')
    partial_config={'extra':(('partial.h','struct Incomplete {'),),'partial':('partial.h',)}
    definitions.extend([('partial-selected-unit',partial_source,tests_module.WRITE,'material',partial_config),
        ('partial-selected-first-not-exact',partial_source,tests_module.FIRST_LOG,'no-log',partial_config),
        ('partial-selected-second-not-exact',partial_source,tests_module.SECOND_LOG,'no-log',partial_config)])
    definitions.append(('known-all-return-unreachable-log', tests_module.KNOWN_ALL_RETURN_SOURCE, tests_module.FIRST_LOG, 'known_gap'))
    for definition in definitions:
        name, source, statement, contract = definition[:4]
        heuristic = len(definition) > 4 and definition[4] == 'heuristic'
        options = definition[4] if len(definition)>4 and isinstance(definition[4],dict) else {}
        fixture_ctx = tests_module.t93.T93ScalarPointerTests().context(source,**options)
        fixture_detector = SensitiveExposureDetector() if heuristic else SensitiveExposureDetector(tests_module.t93.t89.MODEL)
        case_direct = fixture_detector.detect(fixture_ctx, fixture_ctx.units)
        case_registry = DetectorRegistry()
        case_registry.register(fixture_detector)
        case_reports, case_coverage = run_all_with_coverage(fixture_ctx, case_registry)
        line = next(i for i,text in enumerate(source.splitlines(),1) if statement in text) if statement is not None else None
        select = lambda findings: [finding for finding in findings
                                   if finding.file == 'service.cpp' and (line is None or finding.line == line)]
        direct_target = select(case_direct.findings)
        runner_target = select(case_reports[0].diagnostics)
        cases.append({'case': name, 'source': source, 'source_sha256': hashlib.sha256(source.encode()).hexdigest(),
            'model': 'unknown-profile heuristic' if heuristic else 'explicit Callback argument 0 source',
            'cpp_control_flow_contract': next((tests_module.CASE_SEMANTICS[key] for key in sorted(tests_module.CASE_SEMANTICS,key=len,reverse=True) if name==key or name.startswith(key+'-')),None),
            'frontend_parse_status': {unit.path:unit.parse_status for unit in fixture_ctx.units},
            'target_statement': statement, 'after_contract': contract,
            'known_defect': ({'status':'known_gap_not_passed','expected_semantics':'No following write or log is reachable: unique case and complete default both return.',
                'actual':'Legacy conservative scan resurrects fallthrough and reports first log.',
                'scope':'Outside D97 bounded direct-assignment plus break proof; reported to developer and owner.'} if contract=='known_gap' else None),
            'direct_target_candidates': [asdict(finding) for finding in direct_target],
            'runner_target_diagnostics': [finding.to_dict() for finding in runner_target],
            'all_direct_findings': [asdict(finding) for finding in case_direct.findings],
            'all_runner_diagnostics': [finding.to_dict() for finding in case_reports[0].diagnostics],
            'call_facts': fixture_ctx.shared_facts['ast']['service.cpp']['calls'],
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
        flow = LocalFlow(unit, SensitiveSourceModel('fixture/t96', 'a' * 40))
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
        'tests': {'count': tests.testsRun, 'failures': len(tests.failures), 'errors': len(tests.errors), 'log': test_log.getvalue()},
        'source': {**cert, 'files': rows}, 'snapshot_sha256': request.snapshot_sha256,
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
        destination = Path(tempfile.mkdtemp(prefix='t96_' + revision[:10] + '_', dir=args.cache.resolve()))
        with tarfile.open(fileobj=io.BytesIO(archive)) as bundle:
            bundle.extractall(destination, filter='data')
        output = destination / 'probe.json'
        subprocess.run([sys.executable, str(Path(__file__).resolve()), '--snapshot-root', str(destination),
            '--revision', revision, '--cert-git-dir', str(args.cert_git_dir), '--output', str(output)],
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
    def changed_paths(old_value, new_value, prefix=''):
        if isinstance(old_value, dict) and isinstance(new_value, dict):
            return [path for key in sorted(old_value.keys() | new_value.keys())
                    for path in (changed_paths(old_value[key], new_value[key], prefix + '/' + key)
                                 if key in old_value and key in new_value else [prefix + '/' + key])]
        if isinstance(old_value, list) and isinstance(new_value, list) and len(old_value) == len(new_value):
            return [path for index, (a, b) in enumerate(zip(old_value, new_value))
                    for path in changed_paths(a, b, prefix + '/' + str(index))]
        return [prefix] if old_value != new_value else []
    coverage_changes = changed_paths(before['coverage'], after['coverage'])
    version_only = bool(coverage_changes) and all(
        path.endswith('/source_binding/detector_version') for path in coverage_changes)
    result = {'schema': 1, 'study': 'T96 independent switch target joins',
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
            'coverage_changed_paths': coverage_changes,
            'coverage_changed_only_in_binding_version': version_only,
            'coverage_change_explanation': (
                f'Only evidence source_binding.detector_version changed from {before["version"]} to {after["version"]}; '
                'all coverage file statuses, counts, source bindings other than that version, '
                'and diagnostic obligations are unchanged.' if version_only else
                'Inspect coverage_changed_paths; no version-only equality is assumed.'),
            'all_original_call_positions_unchanged': before['call_positions'] == after['call_positions']},
        'interpretation': 'Bounded switch-target compatibility only; direct invocation and '
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
        for field, all_field in (('direct_target_candidates','all_direct_findings'),
                                 ('runner_target_diagnostics','all_runner_diagnostics')):
            contract = case['after_contract']
            selected = case[field]
            all_rows = case[all_field]
            if contract == 'log' and not any('HILOG_INFO' in row['message'] for row in selected):
                raise ValueError('output did not reach log: ' + case['case'])
            if contract == 'material' and not all_rows:
                raise ValueError('material write lost its candidate: ' + case['case'])
            if contract == 'none' and all_rows:
                raise ValueError('literal-only write became material: ' + case['case'])
            if contract == 'no-log' and any('HILOG_INFO' in row['message'] for row in selected):
                raise ValueError('ordinary overwrite left stale log flow: ' + case['case'])


if __name__ == '__main__':
    main()
