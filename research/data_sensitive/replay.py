"""Offline fixed-source D experiment using the real programmatic registry extension."""
import argparse
import hashlib
import json
from pathlib import Path
import resource
import subprocess
import time
from src.ohscanner.execution import run_reviewed_detectors
from src.ohscanner.runner import DetectorRegistry
from src.ohscanner.detectors.data.sensitive_exposure import SensitiveExposureDetector
from src.ohscanner.detectors.data.models import DEFAULT_SOURCE


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--repo-dir',type=Path,required=True)
    parser.add_argument('--output-dir',type=Path,required=True)
    args=parser.parse_args()
    manifest=json.loads((Path(__file__).parent/'source_manifest.json').read_text())
    rows=[r for r in manifest if r['repository']==DEFAULT_SOURCE.repository and r['file'].endswith(('.c','.cpp','.h'))]
    includes=tuple(r['file'] for r in rows)
    for row in rows:
        blob=subprocess.check_output(['git','-C',str(args.repo_dir),'rev-parse',DEFAULT_SOURCE.commit+':'+row['file']]).decode().strip()
        data=subprocess.check_output(['git','-C',str(args.repo_dir),'show',DEFAULT_SOURCE.commit+':'+row['file']])
        assert blob==row['blob'] and hashlib.sha256(data).hexdigest()==row['sha256'], 'Source model manifest mismatch: '+row['file']
    reg=DetectorRegistry();reg.register(SensitiveExposureDetector())
    start=time.perf_counter()
    before=run_reviewed_detectors(args.repo_dir,DEFAULT_SOURCE.repository,DEFAULT_SOURCE.commit,includes,reg)
    after=run_reviewed_detectors(args.repo_dir,DEFAULT_SOURCE.repository,DEFAULT_SOURCE.commit,includes,reg)
    # Independent second execution on exactly the same pinned source/scope/model.
    def identities(report):
        return [(d['file'],d['line'],d['rule_id'],d['source_sha256'],d['diagnostic_id'])
                for run in report['detector_runs'] for d in run['diagnostics']]
    assert before['snapshot_sha256']==after['snapshot_sha256']
    assert identities(before)==identities(after)
    assert before['detector_coverage']==after['detector_coverage']
    args.output_dir.mkdir(parents=True,exist_ok=True)
    hashes={}
    for name,report in [('first.json',before),('replay.json',after)]:
        data=(json.dumps(report,ensure_ascii=False,indent=2)+'\n').encode()
        (args.output_dir/name).write_bytes(data)
        hashes[name]=hashlib.sha256(data).hexdigest()
    summary={'repository':DEFAULT_SOURCE.repository,'commit':DEFAULT_SOURCE.commit,'tree':before['git_tree'],
             'snapshot_sha256':before['snapshot_sha256'],'scope_files':before['scope']['selected_source_files'],
             'scope_paths':list(includes),'detector_id':SensitiveExposureDetector.detector_id,
             'detector_version':SensitiveExposureDetector.version,'status':before['status'],
             'candidate_count':before['diagnostic_count'],'same_scope_replay_equal':True,
             'candidate_added':0,'candidate_removed':0,'comparison_basis':'two executions of same D version, not an older algorithm baseline',
             'coverage':before['detector_coverage'],'report_hashes':hashes,
             'wall_seconds_two_runs':round(time.perf_counter()-start,4),'peak_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
             'environment':before['environment'],'validated_vulnerability':0,
             'limitations':['Selected fixed-file experiment only, not whole-component coverage or independent holdout.','Zero candidates is not proof of no sensitive data leakage.']}
    (args.output_dir/'summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({k:v for k,v in summary.items() if k not in ('coverage','scope_paths','environment')},ensure_ascii=False,indent=2))

if __name__=='__main__':main()
