from __future__ import annotations

import argparse
import dataclasses
import difflib
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
from time import perf_counter

WORKTREE = Path(__file__).resolve().parents[4]
if str(WORKTREE) not in sys.path:
    sys.path.insert(0, str(WORKTREE))

from src.ohscanner.detectors.ark_runtime.analysis import analyze_unit
from src.ohscanner.detectors.ark_runtime.detector import ArkRuntimeTypeSafetyDetector
from src.ohscanner.detectors.ark_runtime.exception_guard import analyze_exception_guard
from src.ohscanner.detectors.ark_runtime.model import (
    AnalysisBudget,
    DETECTOR_ID,
    EXCEPTION_GUARD_RULE_ID,
    RULE_ID,
    RuntimeTypeModel,
    VERSION,
)
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.git_source import GitSource, _git_environment, load_git_sources
from src.ohscanner.runner import DetectorRegistry, run_all_with_coverage

TARGET_PATH = 'ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp'
DEPENDENCY_PATH = 'ecmascript/compiler/new_object_stub_builder.cpp'
REPOSITORY = 'openharmony/arkcompiler_ets_runtime'

CASES = (
    {
        'case_id': 'C9-TO-POS-001',
        'control_id': 'C8-TO-POS-001',
        'rule_id': RULE_ID,
        'kind': 'positive',
        'expected': 'hit',
        'commit': '830e85b40240677039719fcbf14f721ad3b19050',
        'expected_tree': '579712c1ebbb703d17cea422b1572023bed5d8a4',
        'expected_blob': '054451b1be4f39254d56a1683cc9d1c1b5e55018',
        'expected_sha256': '847d54f51e384368f49d4e2dd45e900ce6d305a142638a02dda83e3cc6eca422',
    },
    {
        'case_id': 'C9-TO-FIX-001',
        'control_id': 'C8-TO-FIX-001',
        'rule_id': RULE_ID,
        'kind': 'fixed',
        'expected': 'miss',
        'commit': 'a0e30483ab3e4aead67ecfb5c708489915e447f9',
        'expected_tree': '82af11ced4297818410ccf61906b703d25b69165',
        'expected_blob': '95f54f2875f401afe3167c62f8c1e7799782be8c',
        'expected_sha256': '8751b09dfc53d57338d0937d9c120574cdd4c7dfedd417fda41ccc399be7f74e',
    },
    {
        'case_id': 'C9-EG-POS-001',
        'control_id': 'C8-EG-POS-001',
        'rule_id': EXCEPTION_GUARD_RULE_ID,
        'kind': 'positive',
        'expected': 'hit',
        'commit': 'c758818dbfd0b146a908d43d21f6ca1706c33783',
        'expected_tree': '5d7c18a5d5ccbf48617b3c07ae9353f5f427d07a',
        'expected_blob': '857ad416bc102fcd5d462e9702d2ba7c51f29b6d',
        'expected_sha256': '984e45f2b6ea652c412437be03dda4189549afe4cf77c95713cf0d0c5d361db9',
    },
    {
        'case_id': 'C9-EG-FIX-001',
        'control_id': 'C8-EG-FIX-001',
        'rule_id': EXCEPTION_GUARD_RULE_ID,
        'kind': 'fixed',
        'expected': 'miss',
        'commit': '81ca57487d04ea30cd11c271e86494a4e130f43e',
        'expected_tree': 'f0ddee8ee7f74b3f22e45b174ce96a269b2e57a5',
        'expected_blob': '3b9de9d915d767d7a67316145451da2446162884',
        'expected_sha256': '4684a1587519e7d141f181b595317db489991a3908e1f1b4ef67513c25d9efd0',
    },
)


def jsonable(value):
    if dataclasses.is_dataclass(value):
        return dataclasses.asdict(value)
    if isinstance(value, tuple):
        return [jsonable(item) for item in value]
    if isinstance(value, list):
        return [jsonable(item) for item in value]
    if isinstance(value, dict):
        return {str(key): jsonable(item) for key, item in value.items()}
    return value


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git(repo: Path, *args: str) -> bytes:
    process = subprocess.run(
        ['git', '-c', 'remote.origin.promisor=false', '-C', str(repo), *args],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_git_environment(),
        check=False,
        timeout=30,
    )
    if process.returncode:
        raise RuntimeError('offline git operation failed: ' + ' '.join(args[:3]) + ': '
                           + process.stderr.decode('utf-8', 'replace')[:500])
    return process.stdout


def object_status(repo: Path, oid: str) -> dict:
    process = subprocess.run(
        ['git', '-c', 'remote.origin.promisor=false', '-C', str(repo), 'cat-file', '-t', oid],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_git_environment(),
        check=False,
        timeout=30,
    )
    return {
        'oid': oid,
        'available': process.returncode == 0,
        'object_type': process.stdout.decode('ascii', 'replace').strip() or None,
        'error': None if process.returncode == 0 else process.stderr.decode('utf-8', 'replace')[:300],
    }


def read_bound_source(repo: Path, commit: str, path: str, expected_blob: str,
                      expected_sha256: str) -> tuple[dict, GitSource, str]:
    pinned, tree, sources, inventory = load_git_sources(repo, commit, (path,))
    if pinned != commit or len(sources) != 1:
        raise ValueError('unexpected pinned source scope')
    source = sources[0]
    actual_sha256 = sha256_bytes(source.data)
    if source.oid != expected_blob or actual_sha256 != expected_sha256:
        raise ValueError('source identity mismatch')
    return {
        'repository': REPOSITORY,
        'commit': pinned,
        'tree': tree,
        'path': source.path,
        'blob_oid': source.oid,
        'source_sha256': actual_sha256,
        'bytes': len(source.data),
        'snapshot_sha256': None,
        'git_inventory': inventory,
    }, source, tree


def source_unit(source: GitSource):
    from src.ohscanner.contracts import SourceUnit
    from src.parser.ast import parse_source

    text = source.data.decode('utf-8')
    index = parse_source(text, 'cpp')
    return SourceUnit(
        source.path,
        'cpp',
        text,
        sha256_bytes(source.data),
        index.parse_status,
        tuple(json.dumps(item, sort_keys=True) for item in index.parse_issues),
    ), index


def classify(result) -> str:
    if isinstance(result, dict):
        kinds = {item['kind'] for item in result.get('observations', [])}
        file_outcome = result.get('file_outcome')
        limitations = result.get('limitations', [])
    else:
        kinds = {item.kind for item in result.observations}
        file_outcome = result.file_outcome
        limitations = result.limitations
    if 'candidate' in kinds:
        return 'hit'
    if 'unknown' in kinds:
        return 'unknown'
    if file_outcome == 'not_analyzed' or 'not_applicable_to_rule' in limitations:
        return 'not_analyzed'
    return 'miss'


def raw_rule_result(rule_id: str, unit, model: RuntimeTypeModel, budget: AnalysisBudget) -> dict:
    if rule_id == RULE_ID:
        result = analyze_unit(unit, model=model, budget=budget, research_partial=True)
    else:
        result = analyze_exception_guard(
            unit,
            creator_name=model.exception_guard_creator[0],
            creator_arity=model.exception_guard_creator[1],
            sink_name=model.exception_guard_sink[0],
            sink_arity=model.exception_guard_sink[1],
            sink_glue_arg=model.exception_guard_sink[2],
            sink_object_arg=model.exception_guard_sink[3],
            caller_names=model.exception_guard_callers,
            caller_types=model.exception_guard_caller_types,
            budget=budget,
        )
    payload = jsonable(result)
    payload['classification'] = classify(result)
    return payload


def run_adapter(source: GitSource, unit, index, model: RuntimeTypeModel, commit: str) -> dict:
    from src.ohscanner.contracts import ScanContext, ScanRequest

    units = (unit,)
    request = ScanRequest(
        'c9-current-history-replay',
        model.source_repository,
        commit,
        snapshot_digest(units),
        'current-component:' + model.source_repository,
        provenance='git_object',
        profile_id='light-ast',
    )
    context = ScanContext(
        request,
        units,
        {
            'ast': {source.path: dict(index.to_dict(), parse_status=index.parse_status)},
            'source_blob_oid': {source.path: source.oid},
        },
    )
    registry = DetectorRegistry()
    registry.register(ArkRuntimeTypeSafetyDetector(model=model))
    reports, coverage = run_all_with_coverage(context, registry)
    return {
        'request': jsonable(request),
        'run': jsonable(reports[0]),
        'coverage': jsonable(coverage),
    }


def excerpt(source: GitSource, needles: tuple[str, ...]) -> list[dict]:
    lines = source.data.decode('utf-8').splitlines()
    selected = []
    for needle in needles:
        for number, line in enumerate(lines, 1):
            if needle in line:
                start = max(1, number - 4)
                end = min(len(lines), number + 4)
                selected.append({
                    'needle': needle,
                    'line': number,
                    'start_line': start,
                    'end_line': end,
                    'text': '\n'.join(lines[start - 1:end]),
                })
    unique = {}
    for item in selected:
        unique[(item['needle'], item['line'])] = item
    return list(unique.values())


def dependency_inventory(repo: Path, model: RuntimeTypeModel) -> dict:
    required = []
    dependency_specs = [
        (model.effect_summary_revision, path, blob, None) for path, blob in model.source_dependencies
    ] + list(model.exception_guard_dependencies)
    for revision, path, blob, expected_sha in dependency_specs:
        entry = {
            'revision': revision,
            'path': path,
            'expected_blob': blob,
            'expected_sha256': expected_sha,
        }
        try:
            source, tree, sources, inventory = load_git_sources(repo, revision, (path,))
            if len(sources) != 1:
                raise ValueError('unexpected dependency scope')
            actual = sources[0]
            entry.update({
                'status': 'available' if actual.oid == blob and (expected_sha is None or sha256_bytes(actual.data) == expected_sha)
                else 'mismatch',
                'tree': tree,
                'actual_blob': actual.oid,
                'actual_sha256': sha256_bytes(actual.data),
                'bytes': len(actual.data),
                'git_inventory': inventory,
            })
        except Exception as error:
            entry.update({'status': 'missing_or_unreadable', 'error': str(error)})
        required.append(entry)

    provenance = []
    for path, blob in model.effect_summary_sources:
        state = object_status(repo, blob)
        state.update({'path': path, 'role': 'effect_summary_source'})
        provenance.append(state)

    return {
        'required_execution_dependencies': required,
        'model_provenance_sources': provenance,
        'required_gate': 'pass' if all(item['status'] == 'available' for item in required)
        else 'blocked_missing_or_mismatched_dependency',
        'provenance_gate': 'pass' if all(item['available'] for item in provenance)
        else 'blocked_missing_model_provenance_source',
    }


def write_json(path: Path, payload: dict) -> None:
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=False) + '\n',
        encoding='utf-8',
        newline='\n',
    )


def main() -> int:
    parser = argparse.ArgumentParser(description='Offline Ark Runtime current-rule historical replay')
    parser.add_argument('--repo-dir', required=True)
    parser.add_argument('--output-dir', required=True)
    args = parser.parse_args()
    start = perf_counter()
    repo = Path(args.repo_dir).resolve()
    output = Path(args.output_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)

    model = RuntimeTypeModel()
    budget = AnalysisBudget()
    dependencies = dependency_inventory(repo, model)
    results = []
    sources_by_key = {}
    diffs = []

    for case in CASES:
        identity, source, tree = read_bound_source(
            repo,
            case['commit'],
            TARGET_PATH,
            case['expected_blob'],
            case['expected_sha256'],
        )
        if tree != case['expected_tree']:
            raise ValueError('tree identity mismatch for ' + case['case_id'])
        unit, index = source_unit(source)
        identity['snapshot_sha256'] = snapshot_digest((unit,))
        sources_by_key[source.path + ':' + source.oid] = case['commit']
        raw = raw_rule_result(case['rule_id'], unit, model, budget)
        adapter = run_adapter(source, unit, index, model, case['commit'])
        expected = case['expected']
        actual = raw['classification']
        results.append({
            'case_id': case['case_id'],
            'control_id': case['control_id'],
            'kind': case['kind'],
            'rule_id': case['rule_id'],
            'expected': expected,
            'actual': actual,
            'control_result': 'pass' if actual == expected else 'fail',
            'candidate_count': sum(item['kind'] == 'candidate' for item in raw['observations']),
            'unknown_count': sum(item['kind'] == 'unknown' for item in raw['observations']),
            'matched_count': sum(item['kind'] == 'matched' for item in raw['observations']),
            'source_identity': identity,
            'raw_rule_result': raw,
            'adapter_result': adapter,
            'evidence_status': 'candidate/unassessed',
            'validated_vulnerability': False,
        })

    for left, right, name in (
        (CASES[0], CASES[1], 'type-origin-parent-fix.diff'),
        (CASES[2], CASES[3], 'exception-guard-parent-fix.diff'),
    ):
        left_identity, left_source, _ = read_bound_source(
            repo, left['commit'], TARGET_PATH, left['expected_blob'], left['expected_sha256'])
        right_identity, right_source, _ = read_bound_source(
            repo, right['commit'], TARGET_PATH, right['expected_blob'], right['expected_sha256'])
        diff = ''.join(difflib.unified_diff(
            left_source.data.decode('utf-8').splitlines(keepends=True),
            right_source.data.decode('utf-8').splitlines(keepends=True),
            fromfile=left['commit'] + ':' + TARGET_PATH,
            tofile=right['commit'] + ':' + TARGET_PATH,
            n=8,
        ))
        (output / name).write_text(diff, encoding='utf-8', newline='\n')
        diffs.append({
            'file': name,
            'from': left_identity,
            'to': right_identity,
            'sha256': sha256_bytes(diff.encode('utf-8')),
        })

    excerpts = {
        'type_origin': {
            case['case_id']: excerpt(
                read_bound_source(repo, case['commit'], TARGET_PATH,
                                  case['expected_blob'], case['expected_sha256'])[1],
                ('GateRef newArray =', 'GateRef newArrayType =', 'StoreTypedArrayElement('),
            )
            for case in CASES[:2]
        },
        'exception_guard': {
            case['case_id']: excerpt(
                read_bound_source(repo, case['commit'], TARGET_PATH,
                                  case['expected_blob'], case['expected_sha256'])[1],
                ('GateRef newArray =', 'HasPendingException(glue)', 'GateRef newArrayType ='),
            )
            for case in CASES[2:]
        },
    }
    write_json(output / 'source-excerpts.json', excerpts)

    all_controls_pass = all(item['control_result'] == 'pass' for item in results)
    replay_gate = (
        'pass' if all_controls_pass and dependencies['required_gate'] == 'pass'
        and dependencies['provenance_gate'] == 'pass'
        else 'blocked'
    )
    raw_payload = {
        'schema_version': 'c9.current-history-replay.raw/v1',
        'generated_at_utc': datetime.now(timezone.utc).isoformat(),
        'detector': {
            'detector_id': DETECTOR_ID,
            'rule_ids': [RULE_ID, EXCEPTION_GUARD_RULE_ID],
            'version': VERSION,
            'model_version': model.version,
            'model_digest': model.digest,
            'build_profile': model.build_profile,
            'analysis_budget': jsonable(budget),
        },
        'repository': {
            'declared': REPOSITORY,
            'local_git_dir': str(repo),
            'remote_urls': git(repo, 'remote', '-v').decode('utf-8', 'replace').splitlines(),
        },
        'profile': {'profile_id': 'light-ast', 'provenance': 'git_object'},
        'environment': {
            'python_executable': sys.executable,
            'python_version': platform.python_version(),
            'platform': platform.platform(),
            'argv': sys.argv,
            'cwd': str(Path.cwd()),
            'selected_env': {
                key: os.environ.get(key) for key in (
                    'PYTHONPATH', 'PYTHONDONTWRITEBYTECODE', 'PYTHONHASHSEED',
                    'GIT_NO_LAZY_FETCH', 'GIT_ALLOW_PROTOCOL', 'GIT_TERMINAL_PROMPT',
                    'GIT_NO_REPLACE_OBJECTS', 'OHSCANNER_ARK_REPO',
                )
            },
        },
        'dependency_inventory': dependencies,
        'results': results,
        'diffs': diffs,
        'control_summary': {
            'count': len(results),
            'passed': sum(item['control_result'] == 'pass' for item in results),
            'failed': sum(item['control_result'] == 'fail' for item in results),
            'hit': sum(item['actual'] == 'hit' for item in results),
            'miss': sum(item['actual'] == 'miss' for item in results),
            'unknown': sum(item['actual'] == 'unknown' for item in results),
            'not_analyzed': sum(item['actual'] == 'not_analyzed' for item in results),
        },
        'claim_boundary': {
            'default_status': 'candidate/unassessed',
            'validated_vulnerability': 0,
            'product_vulnerability': False,
            'precision_recall': None,
            'zero_fp_fn_claim': False,
        },
        'elapsed_seconds_internal': perf_counter() - start,
    }
    write_json(output / 'raw-results.json', raw_payload)

    manifest = {
        'schema_version': 'c9.current-history-replay.manifest/v1',
        'run_kind': 'source-bound current Ark Runtime 0.7.0 rule replay',
        'target_repository': REPOSITORY,
        'target_git_dir': str(repo),
        'worktree': str(WORKTREE),
        'head': git(WORKTREE, 'show', '-s', '--format=%H', 'HEAD').decode().strip(),
        'head_tree': git(WORKTREE, 'show', '-s', '--format=%T', 'HEAD').decode().strip(),
        'detector_id': DETECTOR_ID,
        'rule_ids': [RULE_ID, EXCEPTION_GUARD_RULE_ID],
        'detector_version': VERSION,
        'model_version': model.version,
        'model_digest': model.digest,
        'profile_id': 'light-ast',
        'provenance': 'git_object',
        'build_profile': model.build_profile,
        'exact_argv': sys.argv,
        'exact_env_scope': raw_payload['environment']['selected_env'],
        'input_cases': [
            {
                'case_id': item['case_id'],
                'commit': item['source_identity']['commit'],
                'tree': item['source_identity']['tree'],
                'path': item['source_identity']['path'],
                'blob': item['source_identity']['blob_oid'],
                'source_sha256': item['source_identity']['source_sha256'],
                'snapshot_sha256': item['source_identity']['snapshot_sha256'],
            }
            for item in results
        ],
        'dependency_gate': dependencies['required_gate'],
        'model_provenance_gate': dependencies['provenance_gate'],
        'control_gate': 'pass' if all_controls_pass else 'fail',
        'replay_gate': replay_gate,
        'scanner_observation': (
            'known vulnerable parent hit by current rule'
            if results[0]['actual'] == 'hit' and results[2]['actual'] == 'hit'
            else 'known vulnerable parent not fully hit by current rule'
        ),
        'raw_results': 'raw-results.json',
        'source_excerpts': 'source-excerpts.json',
        'diffs': [item['file'] for item in diffs],
        'claim_boundary': raw_payload['claim_boundary'],
    }
    write_json(output / 'replay-manifest.json', manifest)
    print(json.dumps({
        'replay_gate': replay_gate,
        'controls': raw_payload['control_summary'],
        'scanner_observation': manifest['scanner_observation'],
    }, ensure_ascii=False))
    return 0 if all_controls_pass else 2


if __name__ == '__main__':
    raise SystemExit(main())







