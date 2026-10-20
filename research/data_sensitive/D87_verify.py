"""D87 role controls and exact T85 scope; freeze both detector and helper modules."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import types
from D86_verify import ROOT, git, fingerprint
from D84_verify import ScanContext, ScanRequest, snapshot_digest, index_sources, GitSource, summary
from tests.detectors.data.test_d87_property_roles import context, KEY, HAS

BASE = '7d8a25a67f76d962a0196518c394a27c0f03f841'
DETECTOR = 'src/ohscanner/detectors/data/sensitive_exposure.py'
HELPER = 'src/ohscanner/detectors/data/property_keys.py'


def implementation(revision=None):
    def read(path, optional=False):
        if revision:
            result = subprocess.run(['git', 'show', revision + ':' + path], cwd=ROOT,
                                    capture_output=True, check=False)
            if result.returncode and optional:
                return None
            result.check_returncode()
            return result.stdout
        return (ROOT / path).read_bytes()

    source, helper = read(DETECTOR), read(HELPER, optional=True)
    package = 'src.ohscanner.detectors.data'
    helper_name = package + '.property_keys'
    original = sys.modules.get(helper_name)
    if helper is not None:
        module = types.ModuleType(helper_name)
        module.__package__ = package
        sys.modules[helper_name] = module
        exec(compile(helper, (revision or 'worktree') + ':' + HELPER, 'exec'), module.__dict__)
    name = package + '._d87_' + (revision or 'worktree')[:12]
    detector_module = types.ModuleType(name)
    detector_module.__package__ = package
    sys.modules[name] = detector_module
    try:
        exec(compile(source, (revision or 'worktree') + ':' + DETECTOR, 'exec'), detector_module.__dict__)
    finally:
        if original is None:
            sys.modules.pop(helper_name, None)
        else:
            sys.modules[helper_name] = original
    hashes = {DETECTOR: hashlib.sha256(source).hexdigest()}
    if helper is not None:
        hashes[HELPER] = hashlib.sha256(helper).hexdigest()
    return detector_module.SensitiveExposureDetector, hashes


def replay_component(component, store, before, after):
    commit = component['commit']
    assert git(store, 'rev-parse', commit + '^{tree}').decode().strip() == component['tree']
    sources = []
    for row in component['files']:
        data = git(store, 'cat-file', 'blob', commit + ':' + row['path'])
        blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        assert blob == row['blob'] == git(store, 'rev-parse', commit + ':' + row['path']).decode().strip()
        assert len(data) == row['bytes'] and hashlib.sha256(data).hexdigest() == row['sha256']
        sources.append(GitSource(row['path'], 'cpp', blob, data))
    units, ast, _ = index_sources(tuple(sources))
    units = tuple(sorted(units, key=lambda u: u.path))
    request = ScanRequest('d87-fixed-scope-' + component['key'], component['repository'], commit,
                          snapshot_digest(units), 'current-component:' + component['repository'],
                          profile_id='light-ast', provenance='git_object')
    ctx = ScanContext(request, units, {'ast': ast})
    runs = {label: detector().detect(ctx, units) for label, detector in [('before', before), ('after', after)]}
    result = {**component, 'source_commit_tree_blob_verified': True,
              'parse_status': {u.path: u.parse_status for u in units},
              'snapshot_sha256': request.snapshot_sha256,
              **{label: fingerprint(run) for label, run in runs.items()}}
    result['identical_candidates_and_outcomes'] = result['before'] == result['after']
    result['after_binding_notes'] = [item for item in runs['after'].limitations if 'bound constant' in item]
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, default=ROOT / 'research/data_sensitive/T85_SOURCE_MANIFEST.json')
    parser.add_argument('--wifi-git-dir', type=Path, required=True)
    parser.add_argument('--cert-git-dir', type=Path, required=True)
    parser.add_argument('--revision')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    before, before_hashes = implementation(BASE)
    after, after_hashes = implementation(args.revision)
    controls = {}
    for name, source in {
        'bound_global_schema_key': KEY + 'void f(){' + HAS + '}',
        'unknown_wrapper': KEY + 'void f(){UnknownWrapper(CERT_PASSWORD.c_str());}',
        'hardcoded_material_as_key': KEY.replace('"password"', '"real-hardcoded-secret"') + 'void f(){' + HAS + '}',
        'dynamic_material_as_key': KEY + 'void f(const char *password){bool result=false; napi_has_named_property(env,obj,password,&result);}',
        'reference_parameter_shadow': KEY + 'void f(const std::string &CERT_PASSWORD){' + HAS + '}',
        'actual_property_value': KEY + 'void f(){napi_value out=nullptr; napi_get_named_property(env,obj,CERT_PASSWORD.c_str(),&out);\nConsume(out);}',
    }.items():
        ctx = context((('service.cpp', source),))
        controls[name] = {label: summary(detector().detect(ctx, ctx.units))
                          for label, detector in [('before', before), ('after', after)]}
    manifest = json.loads(args.manifest.read_text())
    stores = {'wifi': args.wifi_git_dir, 'cert': args.cert_git_dir}
    studies = [replay_component(c, stores[c['key']], before, after) for c in manifest['components']]
    # An explicitly different diagnostic scope explains why the real key can
    # bind when its unrelated partial logging header is absent. Never present
    # this as the strict three-file before/after comparison.
    cert = next(c for c in manifest['components'] if c['key'] == 'cert')
    diagnostic = dict(cert, key='cert_definition_only_diagnostic',
                      files=[r for r in cert['files'] if not r['path'].endswith('/cf_log.h')])
    diagnostic = replay_component(diagnostic, args.cert_git_dir, before, after)
    result = {'baseline': BASE, 'revision': args.revision or 'working_tree',
              'before_version': before.version, 'after_version': after.version,
              'before_implementation_sha256': before_hashes, 'after_implementation_sha256': after_hashes,
              'controls': controls, 'strict_t85_scope': studies, 'different_diagnostic_scope': diagnostic,
              'limits': ['Only the bound global schema name password in exact NAPI read-key argument 2 is excluded.',
                         'Unknown wrappers, other material operands, API macro/body shadows and partial inputs remain candidates.',
                         'The diagnostic two-file scope is not a same-scope warning reduction.',
                         'No target execution, product leakage or formal accuracy metric is established.']}
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'controls': {k: [v['before']['candidate_count'], v['after']['candidate_count']]
                                   for k, v in controls.items()},
                      'strict_scope': [[s['key'], s['before']['candidate_count'], s['after']['candidate_count']]
                                       for s in studies],
                      'different_diagnostic_scope': [diagnostic['before']['candidate_count'], diagnostic['after']['candidate_count']]}))


if __name__ == '__main__':
    main()
