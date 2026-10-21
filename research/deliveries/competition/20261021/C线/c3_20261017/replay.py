"""Offline C3 census and versioned algorithm comparison; never production admission."""
import argparse
from dataclasses import asdict, replace
from hashlib import sha256
import importlib.util
from importlib.metadata import version
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
from time import perf_counter

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))
from src.ohscanner.detectors.ark_runtime.analysis import analyze_unit
from src.ohscanner.detectors.ark_runtime.model import RuntimeTypeModel, AnalysisBudget, OWNER, VERSION
from src.ohscanner.detectors.ark_runtime.syntax import parse_functions, walk
from src.ohscanner.detectors.ark_runtime.detector import ArkRuntimeTypeSafetyDetector
from src.ohscanner.git_source import load_git_sources
from src.ohscanner.indexing import prepare_git_context
from src.ohscanner.runner import DetectorRegistry, run_all_with_coverage
from tests.detectors.ark_runtime.test_c3_mechanisms import CASES, classify
from tests.detectors.ark_runtime.support import unit, wrap

BASE = '33242fbd2b58e2f510fa74f1521e247fea08db27'
TARGET = 'ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp'
MODEL_SOURCE = 'ecmascript/compiler/new_object_stub_builder.cpp'
BEFORE = '830e85b40240677039719fcbf14f721ad3b19050'
FIXED = 'a0e30483ab3e4aead67ecfb5c708489915e447f9'


def git(repo, *args):
    return subprocess.check_output(['git', '-C', str(repo), *args],
        env=dict(os.environ, GIT_NO_LAZY_FETCH='1', GIT_ALLOW_PROTOCOL=''))


def freeze_c2(directory):
    """Load the actual C2 Git bytes as a research comparator, never a verdict oracle."""
    package = Path(directory)
    for name in ('__init__', 'model', 'syntax', 'runtime_ir', 'type_origin', 'analysis'):
        (package / (name + '.py')).write_bytes(git(ROOT, 'show', BASE + ':src/ohscanner/detectors/ark_runtime/' + name + '.py'))
    spec = importlib.util.spec_from_file_location('ark_c2_frozen', package / '__init__.py',
                                                 submodule_search_locations=[str(package)])
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    from ark_c2_frozen.analysis import analyze_unit as old_analyze
    return old_analyze


def origin_reference(fn, store):
    """Lexical definition evidence only; explicitly not a path/effect proof."""
    args = fn.arguments(store)
    if len(args) != 5:
        return {'status': 'unknown', 'reason': 'arity'}
    target, token = args[1], args[4]
    origin = None
    binding = fn.resolve(fn.text(token), token) if token.type == 'identifier' else None
    if binding:
        for declaration in walk(fn.body):
            if declaration.type == 'init_declarator' and declaration.start_byte <= binding.position < declaration.end_byte:
                for call in walk(declaration):
                    if call.type == 'call_expression' and fn.call_name(call) == 'LoadHClass':
                        operands = fn.arguments(call)
                        if len(operands) == 1:
                            origin = fn.text(operands[0])
    elif token.type == 'call_expression':
        for call in walk(token):
            if call.type == 'call_expression' and fn.call_name(call) == 'LoadHClass':
                operands = fn.arguments(call)
                if len(operands) == 1:
                    origin = fn.text(operands[0])
    return {'mode': 'lexical_definition_reference_not_path_proof', 'line': store.start_point[0] + 1,
            'target_expression': fn.text(target), 'token_expression': fn.text(token),
            'token_load_object': origin, 'same_written_object': origin == fn.text(target) if origin else None}


def run(repo, output):
    started = perf_counter()
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    model = RuntimeTypeModel()
    manifest = json.loads((ROOT / 'research/experiments/ark_runtime/c1_20261017/source_evidence.json').read_text(encoding='utf-8'))
    expected = {(x['commit'], x['path']): x for x in manifest['sources']}
    history, source_records, census = [], [], []
    with tempfile.TemporaryDirectory(prefix='ohscanner-c2-comparator-') as frozen:
        old_analyze = freeze_c2(frozen)
        for commit in (BEFORE, FIXED):
            context, tree, _, _, _ = prepare_git_context(Path(repo), 'openharmony/arkcompiler_ets_runtime', commit, (TARGET,))
            source = context.units[0]
            _, _, objects, _ = load_git_sources(Path(repo), commit, (TARGET, MODEL_SOURCE))
            for obj in objects:
                planned = expected.get((commit, obj.path)) or expected[(FIXED, MODEL_SOURCE)]
                assert obj.oid == planned['blob_oid'] and sha256(obj.data).hexdigest() == planned['source_sha256']
                source_records.append(dict(commit=commit, tree=tree, path=obj.path, blob=obj.oid,
                                           source_sha256=sha256(obj.data).hexdigest(), bytes=len(obj.data)))
            _, _, summaries, _ = load_git_sources(Path(repo), commit, tuple(p for p, _ in model.effect_summary_sources))
            expected_summaries = dict(model.effect_summary_sources)
            if len(summaries) != len(expected_summaries):
                raise ValueError('effect_summary_sources_unavailable')
            for obj in summaries:
                if obj.oid != expected_summaries[obj.path]:
                    raise ValueError('effect_summary_changed_at_pinned_revision:' + obj.path)
                source_records.append(dict(commit=commit, tree=tree, path=obj.path, blob=obj.oid,
                                           source_sha256=sha256(obj.data).hexdigest(), bytes=len(obj.data),
                                           role='reviewed_effect_or_parameter_summary'))
            parsed, functions = parse_functions(source.text.encode('utf-8'))
            errors = [{'kind': n.type, 'missing': n.is_missing, 'start_byte': n.start_byte,
                       'end_byte': n.end_byte, 'line': n.start_point[0] + 1}
                      for n in walk(parsed.root_node) if n.type == 'ERROR' or n.is_missing]
            scoped_model = replace(model, caller_profiles=())
            local = analyze_unit(source, model=scoped_model, research_partial=True)
            baseline = old_analyze(source, research_partial=True)
            registry = DetectorRegistry()
            registry.register(ArkRuntimeTypeSafetyDetector())
            production, coverage = run_all_with_coverage(context, registry)
            target = next(f for f in functions if f.qualified_name == model.caller)
            stores = [n for n in walk(target.body) if n.type == 'call_expression' and target.call_name(n) == model.store_name]
            history.append(dict(commit=commit, snapshot_sha256=context.request.snapshot_sha256,
                profile=context.request.profile_id, build_profile=model.build_profile,
                parse_status=source.parse_status, source_sha256=source.sha256, scope=[TARGET],
                independent_research_execution=local.to_dict(), frozen_c2_comparison=baseline.to_dict(),
                token_references=[origin_reference(target, n) for n in stores],
                production_execution=production[0].to_dict(), production_coverage=coverage,
                differentiation_gate='BLOCKED' if not any(o.kind == ('candidate' if commit == BEFORE else 'matched')
                                                         for o in local.observations) else 'PASS'))
            if commit == FIXED:
                for fn in functions:
                    if not fn.qualified_name.startswith(OWNER + '::'):
                        continue
                    calls = [n for n in walk(fn.body) if n.type == 'call_expression']
                    names = [fn.call_name(n) for n in calls]
                    type_calls = [n for n in names if n in ('GetObjectType', 'LoadHClass')]
                    creators = [n for n in names if n.endswith(('.NewTypedArray', '.NewTypedArraySameType'))]
                    sinks = [n for n in calls if fn.call_name(n) in (model.store_name, 'this->' + model.store_name)]
                    supported = fn.qualified_name in model.callers and tuple(fn.parameter_types) == model.caller_types
                    result = analyze_unit(source, model=replace(model, caller=fn.qualified_name, caller_profiles=()),
                                          research_partial=True) if supported else None
                    if result:
                        reason = ('unknown dependencies/effects: see observation.effect_sites'
                                  if any(o.kind == 'unknown' for o in result.observations) else
                                  'destination-origin or guarded match in bounded model' if result.observations else
                                  'no reached modelled sink')
                    else:
                        reason = 'outside reviewed caller/signature profile' if sinks else 'no corresponding store sink'
                    census.append(dict(symbol=fn.qualified_name, parameter_types=fn.parameter_types,
                        function_region={'start_byte': fn.node.start_byte, 'end_byte': fn.node.end_byte,
                                         'start_line': fn.node.start_point[0] + 1, 'end_line': fn.node.end_point[0] + 1},
                        subtree_parse_status='partial' if fn.node.has_error else 'complete',
                        source_sha256=source.sha256, ast_error_regions=errors,
                        type_source_calls=type_calls, creator_calls=creators, sink_count=len(sinks),
                        sink_references=[origin_reference(fn, n) for n in sinks],
                        independent_same_type_proof='only explicit origin/guard observations; external dependencies unverified',
                        applicable=supported, result=result.to_dict() if result else None,
                        no_candidate_reason=reason, file_parse_status=source.parse_status,
                        dependency_verification='partial: pinned creator/sink blobs; scalar semantics and build binding still obligations'))
    mechanisms = []
    for cid, body, expected_kind, reason in CASES:
        fixture = unit(wrap(body))
        actual = analyze_unit(fixture)
        mechanisms.append(dict(id=cid, source_sha256=fixture.sha256, expected=expected_kind,
            actual=classify(actual), outcome='PASS' if classify(actual) == expected_kind else 'FAIL',
            rationale=reason, result=actual.to_dict(), sample_role='development_not_holdout'))
    legacy = []
    for number in range(1, 13):
        cid = 'C' + str(number).zfill(2)
        if number < 3:
            actual = history[number - 1]['independent_research_execution']
            source_hash = history[number - 1]['source_sha256']
        else:
            fixture = unit((ROOT / 'tests/detectors/ark_runtime/fixtures' / (cid + '.cpp')).read_text(encoding='utf-8'))
            actual = analyze_unit(fixture, model=replace(model, caller_profiles=()), research_partial=True).to_dict()
            source_hash = fixture.sha256
        kinds = [o['kind'] for o in actual['observations']]
        if number in (1, 3):
            passed = kinds == ['candidate']
        elif number in (2, 4, 5, 6):
            passed = kinds == ['matched']
        elif number == 8:
            passed = not kinds and 'not_applicable_to_rule' in actual['limitations']
        elif number == 11:
            passed = actual['file_outcome'] == 'not_analyzed' and 'candidate' not in kinds
        elif number == 12:
            passed = kinds == ['unreachable']
        else:
            passed = 'unknown' in kinds and 'candidate' not in kinds
        legacy.append(dict(id=cid, outcome='PASS' if passed else 'FAIL', source_sha256=source_hash,
                           result=actual, model_scope='Filter only; same C2 semantic caller'))
    modules = {p.relative_to(ROOT).as_posix(): sha256(p.read_bytes()).hexdigest()
               for p in sorted((ROOT / 'src/ohscanner/detectors/ark_runtime').glob('*.py'))}
    payloads = {'C3_HISTORY.json': history, 'C3_SOURCE_EVIDENCE.json': source_records,
        'C3_CENSUS.json': {'repository': 'openharmony/arkcompiler_ets_runtime', 'commit': FIXED,
            'scope': [TARGET], 'scope_limit': 'one pinned compiler builtin file, not the whole Runtime repository',
            'functions': census, 'new_candidates': sum(o['kind'] == 'candidate' for r in census if r['result']
                                                       for o in r['result']['observations'])},
        'C3_MECHANISMS.json': mechanisms, 'C3_LEGACY_CASES.json': legacy,
        'C3_RUN_MANIFEST.json': dict(commit_at_run=git(ROOT, 'rev-parse', 'HEAD').decode().strip(),
            frozen_c2_commit=BASE, implementation_sha256=modules, detector_version=VERSION,
            model=asdict(model), model_sha256=model.digest, budget=asdict(AnalysisBudget()),
            parser_packages={p: version(p) for p in ('tree-sitter', 'tree-sitter-c', 'tree-sitter-cpp')},
            python=platform.python_version(), os=platform.system(),
            argv=['python', 'research/experiments/ark_runtime/c3_20261017/replay.py', '--repo-dir', '<pinned-local-git-store>', '--output', '<new-output>'],
            duration_seconds=perf_counter() - started, rss=None, rss_status='not_measured',
            source_remote='https://github.com/openharmony/arkcompiler_ets_runtime',
            gitcode_cross_check='C2 exact history unavailable; not reclassified as verified',
            precision=None, recall=None, confirmed=0, holdout_executed=False,
            production_partial_admission=False, dynamic_validation='not_executed')}
    for name, data in payloads.items():
        (output / name).write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n', encoding='utf-8', newline='\n')
    hashes = {name: sha256((output / name).read_bytes()).hexdigest() for name in payloads}
    (output / 'C3_ARTIFACT_HASHES.json').write_text(json.dumps(hashes, indent=2) + '\n', encoding='utf-8', newline='\n')
    return {'mechanisms': len(mechanisms), 'mechanism_failures': sum(x['outcome'] == 'FAIL' for x in mechanisms),
            'legacy_case_count': len(legacy), 'legacy_failures': sum(r['outcome'] == 'FAIL' for r in legacy),
            'functions_indexed': len(census), 'applicable_functions': sum(r['applicable'] for r in census),
            'history_gate': [h['differentiation_gate'] for h in history], 'production': [h['production_execution']['status'] for h in history]}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo-dir', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    result = run(args.repo_dir, args.output)
    print(json.dumps(result))
    raise SystemExit(bool(result['mechanism_failures'] or result['legacy_failures']
                          or result['history_gate'] != ['PASS', 'PASS']
                          or result['production'] != ['blocked', 'blocked']))
