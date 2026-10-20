"""Independent fixed-revision cleanup binding tests and same/extended scope replay."""
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
BEFORE = '5c82be52e05a814e7d29a43c6627b5e53a1ad2c0'
EXTRA = ('frameworks/common/v1.0/src/cf_memory.c',
         'frameworks/common/v1.0/inc/cf_memory.h',
         'frameworks/common/v1.0/src/cf_blob.c',
         'interfaces/inner_api/common/cf_blob.h')


def git(git_dir, *args):
    env = os.environ.copy()
    env.update(GIT_NO_LAZY_FETCH='1', GIT_ALLOW_PROTOCOL='', GIT_TERMINAL_PROMPT='0')
    return subprocess.check_output(['git', '-c', 'remote.origin.promisor=false',
        '--git-dir', str(git_dir), *args], env=env, timeout=30, stderr=subprocess.PIPE)


def child(args):
    sys.path.insert(0, str(args.snapshot_root))
    from dataclasses import asdict
    from src.ohscanner.contracts import ScanContext, ScanRequest
    from src.ohscanner.detectors.data.sensitive_exposure import SensitiveExposureDetector
    from src.ohscanner.fixture import snapshot_digest
    from src.ohscanner.frontend import index_sources
    from src.ohscanner.git_source import GitSource
    from src.ohscanner.runner import DetectorRegistry, run_all_with_coverage

    spec = importlib.util.spec_from_file_location('t89_independent_snapshot_tests',
        ROOT / 'tests/detectors/data/test_t89_cleanup_binding.py')
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
    for path in (*expected, *EXTRA):
        data = git(args.cert_git_dir, 'cat-file', 'blob', cert['commit'] + ':' + path)
        blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        if blob != git(args.cert_git_dir, 'rev-parse', cert['commit'] + ':' + path).decode().strip():
            raise ValueError('blob mismatch: ' + path)
        row = {'path': path, 'blob': blob, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
        if path in expected and row != expected[path]:
            raise ValueError('T85 source drift: ' + path)
        sources.append(GitSource(path, 'c' if path.endswith('.c') else 'cpp', blob, data))
        rows.append(row)

    def execute(context, detector):
        direct = detector.detect(context, context.units)
        registry = DetectorRegistry()
        registry.register(detector)
        reports, coverage = run_all_with_coverage(context, registry)
        return {'direct': asdict(direct), 'runner': reports[0].to_dict(), 'coverage': coverage}

    scopes = []
    for scope, selected in (('strict-T85-three-files', sources[:3]),
                            ('extended-definitions-seven-files', sources)):
        units, ast, _ = index_sources(tuple(selected))
        units = tuple(sorted(units, key=lambda unit: unit.path))
        request = ScanRequest('t89-' + scope, cert['repository'], cert['commit'], snapshot_digest(units),
            'current-component:' + cert['repository'], profile_id='light-ast', provenance='git_object')
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
            'snapshot_sha256': request.snapshot_sha256,
            'parse_status': {unit.path: unit.parse_status for unit in units},
            'calls': facts, **execute(ctx, SensitiveExposureDetector())})

    tester = tests_module.T89CleanupBindingTests()
    exact = '#include <stdlib.h>\nvoid CfFree(void *addr){if(addr!=NULL){free(addr);}}\n'
    cases = [
        ('unbound-name', 'void Callback(char *key){CfFree(key);}', 1),
        ('exact-local-cleanup-unbound-allocator', exact + 'void Callback(char *key){CfFree(key);}', 1),
        ('callback-parameter', 'void Callback(const char *key,void(*CfFree)(const char*)){CfFree(key);}', 1),
        ('callback-local-alias', 'void Callback(const char *key,void(*handler)(const char*)){auto CfFree=handler;CfFree(key);}', 1),
        ('same-name-leak', 'void CfFree(char *addr){HILOG_INFO(1,"%{public}s",addr);}\nvoid Callback(char *key){CfFree(key);}', 1),
        ('allocator-macro', exact.replace('#include <stdlib.h>\n',
            '#include <stdlib.h>\nvoid LeakPassword(void *);\n#undef free\n#define free(addr) LeakPassword(addr)\n')
            + 'void Callback(char *key){CfFree(key);}', 1),
        ('guard-macro', exact.replace('#include <stdlib.h>\n',
            '#include <stdlib.h>\nvoid LeakPassword(void *);\n#undef NULL\n#define NULL (LeakPassword(addr),0)\n')
            + 'void Callback(char *key){CfFree(key);}', 1),
        ('copy-before-cleanup', exact + 'void Callback(char *key){char copy[32]={0};memcpy_s(copy,sizeof(copy),key,31);CfFree(key);HILOG_INFO(1,"%{public}s",copy);}', 1),
    ]
    observations = []
    for name, source, expected_after in cases:
        ctx = tester.context(source)
        observations.append({'case': name, 'source': source,
            'source_role': 'Explicit synthetic Callback argument 0',
            'expected_after_has_candidate': bool(expected_after),
            'parse_status': {unit.path: unit.parse_status for unit in ctx.units},
            **execute(ctx, SensitiveExposureDetector(tests_module.MODEL))})
    result = {'revision': args.revision, 'version': SensitiveExposureDetector.version,
        'tests': {'count': tests.testsRun, 'failures': len(tests.failures), 'errors': len(tests.errors), 'log': log.getvalue()},
        'source': {'repository': cert['repository'], 'commit': cert['commit'], 'tree': cert['tree'], 'files': rows},
        'scopes': scopes, 'role_cases': observations,
        'implementation_sha256': {path: hashlib.sha256((args.snapshot_root / path).read_bytes()).hexdigest()
            for path in ('src/ohscanner/detectors/data/sensitive_exposure.py', 'src/ohscanner/detectors/data/models.py')}}
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--after-commit')
    parser.add_argument('--cert-git-dir', type=Path, required=True)
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
        destination = Path(tempfile.mkdtemp(prefix='t89_' + revision[:10] + '_', dir=args.cache.resolve()))
        with tarfile.open(fileobj=io.BytesIO(archive)) as bundle:
            bundle.extractall(destination, filter='data')
        output = destination / 'probe.json'
        subprocess.run([sys.executable, str(Path(__file__).resolve()), '--snapshot-root', str(destination),
            '--revision', revision, '--cert-git-dir', str(args.cert_git_dir), '--output', str(output)],
            check=True, timeout=120)
        row = json.loads(output.read_text(encoding='utf-8'))
        row['src_archive_sha256'] = hashlib.sha256(archive).hexdigest()
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
    result = {'study': 'T89 independent cleanup binding and callable-shadow tests', 'runs': runs,
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
