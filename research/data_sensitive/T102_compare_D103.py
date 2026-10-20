"""Compare independent fixed replay to developer evidence after independent execution."""
import argparse,hashlib,json
from pathlib import Path


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('independent','manifest','developer','output'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args()
    if not args.developer.exists():
        args.output.write_text(json.dumps({'status':'not_run','reason':'Developer artifact unavailable; independent replay remains separately valid.'},indent=2)+'\n',encoding='utf-8');return
    own=json.loads(args.independent.read_text(encoding='utf-8'))['runs'][-1]
    manifest=json.loads(args.manifest.read_text(encoding='utf-8'))
    dev=json.loads(args.developer.read_text(encoding='utf-8'));scan=dev['scan']
    core=lambda rows:sorted((r['path'],r['blob'],r['bytes'],r['sha256']) for r in rows)
    our_calls=sorted((path,c['name'],tuple(c['arguments']),c['line'],c['start_byte'],c['end_byte'],c['original_span_sha256']) for path,calls in own['call_facts'].items() for c in calls)
    dev_calls=sorted((c['file'],c['name'],tuple(c['arguments']),c['line'],c['start_byte'],c['end_byte'],c['raw_span_sha256']) for c in scan['calls'])
    checks={'scanner_revision_same':own['scanner_revision']==dev['scanner_revision'],
        'source_commit_tree_same':(manifest['commit'],manifest['tree'])==(dev['manifest']['commit'],dev['manifest']['tree']),
        'source_path_blob_bytes_sha_same':core(manifest['source_files'])==core(dev['manifest']['source_files']),
        'source_snapshot_same':own['snapshot_sha256']==scan['request']['snapshot_sha256'],
        'build_target_source_set_same':sorted(manifest['build_boundary']['literal_target_sources'])==sorted(dev['manifest']['declared_target_sources']),
        'unselected_target_cpp_same':sorted(manifest['build_boundary']['unselected_target_sources'])==sorted(dev['manifest']['target_sources_not_scanned']),
        'direct_run_same':own['direct']==scan['direct'],
        'runner_status_same':own['runner']['status']==scan['runner']['status'],
        'runner_diagnostics_same':own['runner']['diagnostics']==scan['runner']['diagnostics'],
        'coverage_same':own['coverage']==scan['coverage'],'all_217_original_call_records_same':our_calls==dev_calls}
    result={'schema':1,'status':'matched' if all(checks.values()) else 'difference_requires_review',
        'independent_replay_sha256':hashlib.sha256(args.independent.read_bytes()).hexdigest(),
        'manifest_sha256':hashlib.sha256(args.manifest.read_bytes()).hexdigest(),
        'developer_artifact_sha256':hashlib.sha256(args.developer.read_bytes()).hexdigest(),
        'checks':checks,'interpretation':'Independent execution preceded this comparison. Matching blocked zero-candidate output is not a safety or accuracy conclusion; runtime IDs/timing are not compared.'}
    args.output.write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n',encoding='utf-8');print(json.dumps(result))

if __name__=='__main__':main()
