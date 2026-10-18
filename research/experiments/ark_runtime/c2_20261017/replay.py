"""Explicit, offline C2 experiments on local pinned Git objects.

No clone/fetch, target builds, or target code execution. Production Runner and
function-local research results are intentionally separate records.
"""
import argparse
from dataclasses import asdict
from hashlib import sha256
from importlib.metadata import version
import json
from pathlib import Path
import platform
import subprocess
import sys
from time import perf_counter

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))

from src.ohscanner.contracts import SourceUnit
from src.ohscanner.detectors.ark_runtime.analysis import analyze_unit
from src.ohscanner.detectors.ark_runtime.model import DETECTOR_ID, RULE_ID, VERSION, RuntimeTypeModel
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.git_source import load_git_sources
from src.ohscanner.indexing import prepare_git_context
from src.ohscanner.runner import DetectorRegistry, run_all_with_coverage
from src.parser.ast import parse_source

MANIFEST = ROOT / 'research/experiments/ark_runtime/c1_20261017/source_evidence.json'
CASES = ROOT / 'research/experiments/ark_runtime/c1_20261017/case_matrix.json'
TARGET = 'ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp'


def pinned_context(repo, commit, expected_sha):
    context, tree, inventory, coverage, sources = prepare_git_context(
        Path(repo), 'openharmony/arkcompiler_ets_runtime', commit, (TARGET,))
    if len(context.units) != 1 or context.units[0].sha256 != expected_sha:
        raise ValueError('historical_source_sha_mismatch')
    return context, tree, inventory, coverage, sources


def replay_history(repo):
    from src.ohscanner.detectors.ark_runtime.detector import ArkRuntimeTypeSafetyDetector
    manifest = json.loads(MANIFEST.read_text(encoding='utf-8'))
    records = []
    for source in manifest['sources']:
        commit, tree, git_sources, inventory = load_git_sources(Path(repo), source['commit'], (source['path'],))
        if len(git_sources) != 1:
            raise ValueError('unexpected_source_scope')
        actual = git_sources[0]
        if actual.oid != source['blob_oid'] or sha256(actual.data).hexdigest() != source['source_sha256']:
            raise ValueError('pinned_source_manifest_mismatch')
        records.append({'commit': commit, 'tree': tree, 'path': actual.path, 'blob': actual.oid,
                        'source_sha256': source['source_sha256'], 'bytes': len(actual.data),
                        'local_git_object_verified': True})
    model_source = manifest['sources'][2]
    before = manifest['target']['before_commit']
    _, model_tree, model_units, _ = load_git_sources(Path(repo), before, (model_source['path'],))
    if (len(model_units) != 1 or model_units[0].oid != model_source['blob_oid']
            or sha256(model_units[0].data).hexdigest() != model_source['source_sha256']):
        raise ValueError('creator_semantic_model_changed_between_historical_revisions')
    records.append({'commit': before, 'tree': model_tree, 'path': model_source['path'],
                    'blob': model_source['blob_oid'], 'source_sha256': model_source['source_sha256'],
                    'bytes': len(model_units[0].data), 'local_git_object_verified': True})
    historical = []
    for number, record in zip(('C01', 'C02'), records[:2]):
        context, tree, inventory, coverage, sources = pinned_context(repo, record['commit'], record['source_sha256'])
        start = perf_counter()
        local = analyze_unit(context.units[0], research_partial=True)
        duration = perf_counter() - start
        registry = DetectorRegistry()
        registry.register(ArkRuntimeTypeSafetyDetector())
        production, sidecar = run_all_with_coverage(context, registry)
        # Re-read the exact same local objects; there is never a moving HEAD.
        context2, tree2, _, _, _ = pinned_context(repo, record['commit'], record['source_sha256'])
        if tree != tree2 or context.request.snapshot_sha256 != context2.request.snapshot_sha256:
            raise ValueError('pinned_inputs_changed_during_run')
        historical.append({
            'case': number, 'source': record,
            'snapshot_sha256': context.request.snapshot_sha256, 'profile': context.request.profile_id,
            'parse_status': context.units[0].parse_status,
            'research_execution': {'mode': 'independent_function_local_research',
                                   'elapsed_seconds': duration, 'result': local.to_dict()},
            'production_execution': {'mode': 'unchanged_public_runner',
                                     'result': production[0].to_dict(), 'coverage': sidecar},
        })
    return records, historical


def case_results(repo):
    sources, history = replay_history(repo)
    matrix = json.loads(CASES.read_text(encoding='utf-8'))
    results = []
    for planned in matrix['cases']:
        number = planned['id']
        if number in ('C01', 'C02'):
            record = next(h for h in history if h['case'] == number)
            actual = record['research_execution']['result']
            identity = record['source']
        else:
            path = ROOT / 'tests/detectors/ark_runtime/fixtures' / (number + '.cpp')
            text = path.read_bytes().decode('utf-8')
            index = parse_source(text, 'cpp')
            source = SourceUnit('fixtures/' + number + '.cpp', 'cpp', text,
                                sha256(text.encode()).hexdigest(), index.parse_status,
                                tuple(json.dumps(x, sort_keys=True) for x in index.parse_issues))
            actual = analyze_unit(source, research_partial=True).to_dict()
            identity = {'provenance': 'self_authored_synthetic_fixture', 'file': source.path,
                        'source_sha256': source.sha256, 'snapshot_sha256': snapshot_digest((source,))}
        kinds = [o['kind'] for o in actual['observations']]
        if number in ('C01', 'C03'):
            passed = 'candidate' in kinds
        elif number in ('C02', 'C04', 'C05', 'C06'):
            passed = 'matched' in kinds and 'candidate' not in kinds and 'unknown' not in kinds
        elif number == 'C08':
            passed = not kinds and 'not_applicable_to_rule' in actual['limitations']
        elif number == 'C11':
            passed = actual['file_outcome'] == 'not_analyzed' and 'candidate' not in kinds
        elif number == 'C12':
            passed = kinds == ['unreachable']
        else:
            passed = 'unknown' in kinds and 'candidate' not in kinds
        results.append({'case': number, 'name': planned['name'], 'expected': planned['expected_if_supported'],
                        'outcome': 'PASS' if passed else 'FAIL', 'source': identity, 'analysis': actual})
    return sources, history, results


def write_report(repo, output):
    start = perf_counter()
    sources, history, results = case_results(repo)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    model = RuntimeTypeModel()
    implementation = {
        path.relative_to(ROOT).as_posix(): sha256(path.read_bytes()).hexdigest()
        for path in sorted((ROOT / 'src/ohscanner/detectors/ark_runtime').glob('*.py'))
    }
    report = {'experiment_kind': 'C2_fixed_scope_rule_behavior_not_accuracy',
              'detector': DETECTOR_ID, 'rule': RULE_ID, 'version': VERSION,
              'candidate_cwe': 'CWE-843',
              'model_sha256': model.digest, 'implementation_sha256': implementation,
              'case_count': len(results), 'passed': sum(r['outcome'] == 'PASS' for r in results),
              'failed': sum(r['outcome'] == 'FAIL' for r in results), 'cases': results,
              'precision': None, 'recall': None, 'confirmed_vulnerabilities': 0}
    payloads = {'test_results.json': report,
                'historical_results.json': history,
                'source_evidence.json': {'repository': 'openharmony/arkcompiler_ets_runtime',
                                         'remote': 'https://github.com/openharmony/arkcompiler_ets_runtime',
                                         'gitcode_cross_check': 'unavailable: upload-pack not our ref for pinned parent',
                                         'sources': sources, 'cve_mapping': 'unknown',
                                         'license': 'Apache-2.0 headers inspected; source bytes not committed'},
                'run_manifest.json': {
                    'experiment_kind': report['experiment_kind'], 'detector': DETECTOR_ID, 'version': VERSION,
                    'rule': RULE_ID, 'model_sha256': model.digest, 'implementation_sha256': implementation,
                    'python': platform.python_version(), 'platform': platform.system(),
                    'packages': {p: version(p) for p in ('tree-sitter', 'tree-sitter-c', 'tree-sitter-cpp')},
                    'scope': [TARGET], 'elapsed_seconds': perf_counter() - start,
                    'memory_rss': None, 'memory_measurement_status': 'not_measured',
                    'argv': ['python', 'research/experiments/ark_runtime/c2_20261017/replay.py',
                             '--repo-dir', '<local-pinned-git-object-store>', '--output', '<result-directory>'],
                    'path_redaction': 'machine-specific cache/output arguments omitted; no source identities redacted',
                    'git_head_at_run': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
                    'notes': ['Independent partial research is not production Runner admission.',
                              'Generated path witnesses are symbolic, not product trigger proofs.',
                              '12 cases are development controls, not independent holdout.',
                              'No target build or PoC was executed.'],
                }}
    for name, value in payloads.items():
        (output / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8', newline='\n')
    hashes = {name: sha256((output / name).read_bytes()).hexdigest() for name in payloads}
    (output / 'artifact_hashes.json').write_text(json.dumps(hashes, indent=2) + '\n', encoding='utf-8', newline='\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo-dir', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    result = write_report(args.repo_dir, args.output)
    print(json.dumps({k: result[k] for k in ('case_count', 'passed', 'failed')}, ensure_ascii=False))
    raise SystemExit(bool(result['failed']))
