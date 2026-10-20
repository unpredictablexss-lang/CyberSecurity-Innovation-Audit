"""D86 before/after semantic controls and T85 manifest-bound real C++ replay."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
from D84_verify import ROOT, TARGET, SensitiveTests, ScanContext, ScanRequest, snapshot_digest
from D84_verify import index_sources, GitSource, SensitiveExposureDetector, baseline_detector, summary

BASE = '1e3b4c0cf02a1d5b0a817cc86dc746d28751b1e8'


def git(store, *args):
    env = os.environ.copy()
    env.update(GIT_NO_LAZY_FETCH='1', GIT_ALLOW_PROTOCOL='', GIT_TERMINAL_PROMPT='0')
    return subprocess.check_output(['git', '-c', 'remote.origin.promisor=false',
                                   '--git-dir', str(store), *args], env=env, timeout=30)


def fingerprint(run):
    return {'status': run.status, 'file_outcomes': list(run.file_outcomes),
            'candidate_count': len(run.findings),
            'findings': [{'file': f.file, 'line': f.line, 'rule': f.rule_id,
                          'message_sha256': hashlib.sha256(f.message.encode()).hexdigest(),
                          'obligations': [o.kind for o in f.evidence_obligations]}
                         for f in run.findings]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--wifi-git-dir', type=Path, required=True)
    parser.add_argument('--cert-git-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--revision', help='Optional fixed implementation Git commit to replay.')
    args = parser.parse_args()
    before = baseline_detector(BASE)
    current = baseline_detector(args.revision) if args.revision else SensitiveExposureDetector
    controls = {}
    for name, body in {
        'hardcoded_secret': 'password="actual-secret"; HILOG_INFO(1,"%{public}s",password);',
        'ambiguous_property_key_spelling': 'password="password"; HILOG_INFO(1,"%{public}s",password);',
        'ambiguous_redaction_spelling': 'password="<redacted>"; HILOG_INFO(1,"%{public}s",password);',
        'empty_literal': 'password=""; HILOG_INFO(1,"%{public}s",password);',
        'unknown_return': 'password=GetOpaqueValue(); HILOG_INFO(1,"%{public}s",password);',
        'type_alignment': 'HILOG_INFO(1,"%{public}zu",alignof(decltype(password)));',
        'unevaluated_call': 'HILOG_INFO(1,"%{public}zu",alignof(decltype(UsePassword(password))));',
        'evaluated_call': 'UsePassword(password);',
        'mixed_runtime_material': 'HILOG_INFO(1,"%{public}u",(unsigned)*password + alignof(decltype(password)));',
    }.items():
        context = SensitiveTests().context('const char *UsePassword(const char *); '
                                          'void f(const char *password){' + body + '}')
        controls[name] = {label: summary(detector().detect(context, context.units))
                          for label, detector in [('before', before), ('after', current)]}
    manifest = json.loads(args.manifest.read_text())
    stores = {'wifi': args.wifi_git_dir, 'cert': args.cert_git_dir}
    studies = []
    for component in manifest['components']:
        store, commit = stores[component['key']], component['commit']
        assert git(store, 'rev-parse', commit + '^{tree}').decode().strip() == component['tree']
        sources = []
        for row in component['files']:
            data = git(store, 'cat-file', 'blob', commit + ':' + row['path'])
            blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
            assert blob == row['blob'] == git(store, 'rev-parse', commit + ':' + row['path']).decode().strip()
            assert len(data) == row['bytes'] and hashlib.sha256(data).hexdigest() == row['sha256']
            sources.append(GitSource(row['path'], 'cpp', blob, data))
        units, ast, _ = index_sources(tuple(sources))
        units = tuple(sorted(units, key=lambda unit: unit.path))
        repository = component['repository']
        request = ScanRequest('d86-real-cpp-' + component['key'], repository, commit,
                              snapshot_digest(units), 'current-component:' + repository,
                              profile_id='light-ast', provenance='git_object')
        context = ScanContext(request, units, {'ast': ast})
        runs = {label: fingerprint(detector().detect(context, units))
                for label, detector in [('before', before), ('after', current)]}
        studies.append({**component, 'source_commit_tree_blob_verified': True,
                        'snapshot_sha256': request.snapshot_sha256, **runs,
                        'identical_candidates_and_outcomes': runs['before'] == runs['after']})
    implementation = (subprocess.check_output(['git', 'show', args.revision + ':' + TARGET], cwd=ROOT)
                      if args.revision else (ROOT / TARGET).read_bytes())
    result = {'baseline': BASE, 'current_detector_version': current.version,
              'current_revision': args.revision or 'working_tree',
              'current_implementation_sha256': hashlib.sha256(implementation).hexdigest(),
              'manifest_sha256': hashlib.sha256(args.manifest.read_bytes()).hexdigest(),
              'controls': controls, 'real_cpp': studies,
              'limits': ['Compile-time C++ type alignment is excluded, not arbitrary empty taint or hard-coded values.',
                         'Named literal controls do not prove public/secret policy or formal accuracy.',
                         'The two real components use unknown-profile heuristics and remain partial/blocked.',
                         'No target runtime execution, product visibility or impact was established.']}
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'controls': {k: [v['before']['candidate_count'], v['after']['candidate_count']]
                                   for k, v in controls.items()},
                      'real_cpp': [{'key': s['key'], 'counts': [s['before']['candidate_count'],
                                                              s['after']['candidate_count']],
                                    'identical': s['identical_candidates_and_outcomes']} for s in studies]}))


if __name__ == '__main__':
    main()
