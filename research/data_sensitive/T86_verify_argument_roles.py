"""Independent T86 synthetic role controls plus exact T85 certificate replay."""
from __future__ import annotations
import argparse
from dataclasses import asdict
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import types
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from research.data_sensitive.T85_real_cpp_replay import detector_at, git
from src.ohscanner.contracts import ScanContext, ScanRequest
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.frontend import index_sources
from src.ohscanner.git_source import GitSource
import tests.detectors.data.test_t86_argument_roles as independent

BASELINE = '7d8a25a67f76d962a0196518c394a27c0f03f841'


def fixed_detector(commit):
    dependencies = {}
    path = 'src/ohscanner/detectors/data/property_keys.py'
    result = subprocess.run(['git', '-C', str(ROOT), 'show', commit + ':' + path],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode == 0:
        name = 'src.ohscanner.detectors.data.property_keys'
        module = types.ModuleType(name)
        module.__package__ = name.rsplit('.', 1)[0]
        sys.modules[name] = module
        exec(compile(result.stdout, commit + ':' + path, 'exec'), module.__dict__)
        dependencies[path] = hashlib.sha256(result.stdout).hexdigest()
    detector, digest = detector_at(commit)
    return detector, digest, dependencies


def roles(call):
    name, args = call['name'], call['arguments']
    known = {}
    if name in ('napi_has_named_property', 'napi_get_named_property') and len(args) == 4:
        known = {0: 'environment', 1: 'object', 2: 'property_name', 3: 'output_handle_or_boolean'}
    elif name == 'napi_set_named_property' and len(args) == 4:
        known = {0: 'environment', 1: 'object', 2: 'property_name', 3: 'property_value'}
    elif name == 'HILOG_INFO':
        known = {0: 'module', 1: 'format', **{i: 'log_operand' for i in range(2, len(args))}}
    elif name == 'LOGE':
        known = {0: 'wrapper_format', **{i: 'wrapper_operand' for i in range(1, len(args))}}
    return {'callee': name, 'line': call['line'], 'arguments': [
        {'index': i, 'expression': arg, 'syntax_role': known.get(i, 'unknown')}
        for i, arg in enumerate(args)]}


def context(sources, repository, commit):
    selected = []
    for path, data in sources:
        blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        selected.append(GitSource(path, 'cpp', blob, data))
    units, ast, _ = index_sources(tuple(selected))
    units = tuple(sorted(units, key=lambda unit: unit.path))
    request = ScanRequest('t86-independent', repository, commit, snapshot_digest(units),
        'current-component:' + repository, profile_id='light-ast', provenance='git_object'
        if repository != 'fixture/t86' else 'fixture')
    return ScanContext(request, units, {'ast': ast})


def run_record(detector, ctx):
    run = detector.detect(ctx, ctx.units)
    annotated = []
    for finding in run.findings:
        calls = ctx.shared_facts['ast'][finding.file]['calls']
        annotated.append({'candidate': asdict(finding), 'calls_on_candidate_line': [roles(call)
            for call in calls if call['line'] == finding.line]})
    return {'candidate_count': len(run.findings), 'run': asdict(run),
            'annotated_candidates': annotated,
            'parse_status': {unit.path: unit.parse_status for unit in ctx.units}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--after-commit', required=True)
    parser.add_argument('--cert-git-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'[0-9a-f]{40}', args.after_commit):
        raise ValueError('--after-commit must be a fixed full SHA')
    common_diff = subprocess.check_output(['git', '-C', str(ROOT), 'diff', BASELINE, '--',
        'src/ohscanner', ':!src/ohscanner/detectors/data/sensitive_exposure.py',
        ':!src/ohscanner/detectors/data/property_keys.py'])
    if common_diff:
        raise ValueError('shared scanner runtime differs from frozen owner baseline')
    fixture_cases = json.loads((ROOT / 'research/data_sensitive/T86_argument_role_cases.json').read_text())['cases']
    manifest = json.loads((ROOT / 'research/data_sensitive/T85_SOURCE_MANIFEST.json').read_text())
    cert = next(component for component in manifest['components'] if component['key'] == 'cert')
    if git(args.cert_git_dir, 'rev-parse', cert['commit'] + '^{tree}').decode().strip() != cert['tree']:
        raise ValueError('certificate tree mismatch')
    sources = []
    for row in cert['files']:
        data = git(args.cert_git_dir, 'cat-file', 'blob', cert['commit'] + ':' + row['path'])
        blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        tree_blob = git(args.cert_git_dir, 'rev-parse', cert['commit'] + ':' + row['path']).decode().strip()
        if blob != row['blob'] or blob != tree_blob or len(data) != row['bytes'] \
                or hashlib.sha256(data).hexdigest() != row['sha256']:
            raise ValueError('certificate source mismatch: ' + row['path'])
        sources.append((row['path'], data))
    actual = context(sources, cert['repository'], cert['commit'])
    results = []
    for label, commit in (('before', BASELINE), ('after', args.after_commit)):
        detector, digest, dependencies = fixed_detector(commit)
        independent.SensitiveExposureDetector = lambda current=detector: current
        log = io.StringIO()
        tests = unittest.TextTestRunner(stream=log, verbosity=2).run(
            unittest.defaultTestLoader.loadTestsFromModule(independent))
        fixtures = []
        for case in fixture_cases:
            ctx = context((('sample.cpp', case['source'].encode()),), 'fixture/t86', 'a' * 40)
            fixtures.append({**case, 'calls': [roles(call) for call in ctx.shared_facts['ast']['sample.cpp']['calls']],
                             **run_record(detector, ctx)})
        results.append({'label': label, 'commit': commit, 'version': detector.version,
            'implementation_sha256': digest, 'support_module_sha256': dependencies,
            'tests': {'count': tests.testsRun,
                'failures': len(tests.failures), 'errors': len(tests.errors), 'log': log.getvalue()},
            'fixtures': fixtures, 'real_source': run_record(detector, actual)})
    before, after = results
    old = {(f['file'], f['line'], f['rule_id'], f['symbol']): f
           for f in before['real_source']['run']['findings']}
    new = {(f['file'], f['line'], f['rule_id'], f['symbol']): f
           for f in after['real_source']['run']['findings']}
    output = {'schema': 1, 'study': 'T86 independent property-name argument role feedback',
        'shared_runtime': {'owner_baseline': BASELINE, 'tracked_common_src_matches': True},
        'source_manifest': cert, 'results': results,
        'real_source_difference': {'added_sites': [list(site) for site in sorted(new.keys() - old.keys())],
            'removed_sites': [list(site) for site in sorted(old.keys() - new.keys())],
            'changed_evidence_sites': [list(site) for site in sorted(new.keys() & old.keys()) if new[site] != old[site]],
            'coverage_equal': before['real_source']['run']['file_outcomes'] == after['real_source']['run']['file_outcomes']},
        'interpretation': 'Argument-role annotations describe observed syntax/API signatures, not compiler binding '
            'or product labels. Candidate/source/sink/role/coverage retained per case. No accuracy or runtime claim.'}
    args.output.write_text(json.dumps(output, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print(json.dumps({'before_tests': {k:v for k,v in before['tests'].items() if k != 'log'},
        'after_tests': {k:v for k,v in after['tests'].items() if k != 'log'},
        'real_counts': [r['real_source']['candidate_count'] for r in results],
        'real_difference': output['real_source_difference']}))
    if after['tests']['failures'] or after['tests']['errors']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
