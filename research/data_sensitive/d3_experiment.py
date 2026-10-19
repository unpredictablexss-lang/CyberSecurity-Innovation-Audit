"""Offline D3 real-Git experiments: public execution and labelled private audit."""
import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import subprocess

from src.ohscanner.indexing import prepare_git_context, environment_fingerprint
from src.ohscanner.execution import run_reviewed_detectors
from src.ohscanner.runner import DetectorRegistry
from src.ohscanner.detectors.data.models import DEFAULT_SOURCE
from src.ohscanner.detectors.data.historical import historical_model, HistoricalLocalFlow, HistoricalSensitiveExposureDetector
from src.ohscanner.detectors.data.sensitive_exposure import LocalFlow, SensitiveExposureDetector

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
def sha(data): return hashlib.sha256(data).hexdigest()
def save(path, value):
    data = (json.dumps(value, ensure_ascii=False, indent=2)+'\n').encode()
    path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data)
    return sha(data)
def errors(tree):
    stack=[tree.root_node]; out=[]
    while stack:
        n=stack.pop(); stack.extend(reversed(n.children))
        if n.is_error or n.is_missing:
            out.append({'kind':n.type,'missing':n.is_missing,'start_line':n.start_point[0]+1,'end_line':n.end_point[0]+1})
    return out
def audit(unit, source, flow, coverage):
    findings=flow.run(); regions=errors(flow.tree)
    funcs=[]
    for f in flow.function_audits:
        funcs.append(dict(f,error_overlap=any(e['start_line']<=f['end_line'] and e['end_line']>=f['start_line'] for e in regions)))
    return {'file':unit.path,'blob':source.oid,'source_sha256':unit.sha256,'parse_status':unit.parse_status,
        'public_outcome':coverage,'detector_scheduled_for_file':coverage in ('partial','complete'),
        'function_count':len(funcs),'functions':funcs,'error_regions':regions,
        'source_sites':list({(s['line'],s['description']):s for s in flow.source_sites}.values()),
        'sink_sites':list({(s['line'],s['symbol']):s for s in flow.sink_sites}.values()),
        'private_probe_findings':[asdict(x) for x in findings],'limitations':sorted(flow.gaps),
        'private_probe_is_public_scan':False,
        'minimal_fix':'Owner-reviewed local admission and macro/type facts; declarations require separate facts, no automatic complete promotion.',
        'candidate_effect':'Withheld production analysis may hide candidates; private observations do not close production coverage.'}
def execute(repo, model, includes, detector, out, name, historical=False):
    context,tree,inventory,parsing,sources=prepare_git_context(repo,model.repository,model.commit,includes)
    reg=DetectorRegistry();reg.register(detector)
    a=run_reviewed_detectors(repo,model.repository,model.commit,includes,reg)
    b=run_reviewed_detectors(repo,model.repository,model.commit,includes,reg)
    def ids(r): return [(x['diagnostic_id'],x['source_sha256']) for run in r['detector_runs'] for x in run['diagnostics']]
    assert ids(a)==ids(b) and a['detector_coverage']==b['detector_coverage']
    cov=a['detector_coverage']['detectors'][detector.detector_id]
    outcomes={f:'complete' for f in cov['analyzed_files']}
    outcomes.update({f:'partial' for f in cov['partially_inspected_files']})
    outcomes.update({x['file']:x['analysis_status'] for x in cov['unexamined']})
    files=[]; repeated=[]
    for unit,source in zip(context.units,sources):
        if historical:
            p=model.profile
            expected={r['file']:r['sha256'] for r in p['required_files']}
            assert expected[unit.path]==sha(source.data)
            flow=HistoricalLocalFlow(unit,model)
            again=HistoricalLocalFlow(unit,model)
        else:
            flow=LocalFlow(unit,model);again=LocalFlow(unit,model)
        row=audit(unit,source,flow,outcomes[unit.path]); files.append(row)
        assert row['private_probe_findings']==[asdict(x) for x in again.run()]
        repeated.append(True)
    return {'name':name,'repository':model.repository,'commit':model.commit,'tree':tree,
        'scope_manifest':includes,'snapshot_sha256':a['snapshot_sha256'],
        'detector_version':detector.version,'model_version':model.profile['model_version'] if historical else '0.1.0',
        'parser_build_profile':{'environment':environment_fingerprint(),'build':'syntax-only, no preprocessing/compiler/link selection'},
        'public_candidate_count':a['diagnostic_count'],'public_coverage':cov['coverage_counts'],
        'public_report_hashes':{'first':save(out/(name+'-public-first.json'),a),'second':save(out/(name+'-public-second.json'),b)},
        'public_repeat_equal':True,'private_repeat_equal':all(repeated),'files':files,
        'private_candidate_count':sum(len(x['private_probe_findings']) for x in files),
        'validated_vulnerability':0,'product_impact':'unknown','private_probe_registered_in_catalog':False}

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--history-repo',type=Path,required=True)
    parser.add_argument('--baseline-repo',type=Path,required=True);parser.add_argument('--output-dir',type=Path,required=True)
    args=parser.parse_args();results=[]
    manifest=json.loads((HERE/'source_manifest.json').read_text())
    paths=tuple(r['file'] for r in manifest if r['repository']==DEFAULT_SOURCE.repository and r['file'].endswith(('.c','.cpp','.h')))
    results.append(execute(args.baseline_repo,DEFAULT_SOURCE,paths,SensitiveExposureDetector(),args.output_dir,'nine-file-baseline'))
    for name,commit in [('tcp-before','d33177135ec6c6aaf4a4c42de1f6878652b330e3'),('tcp-after','63efce3ff7f2708527eb29216decaf5fe2dc33d0')]:
        model=historical_model(commit);paths=tuple(r['file'] for r in model.profile['required_files'])
        results.append(execute(args.history_repo,model,paths,HistoricalSensitiveExposureDetector(model),args.output_dir,name,True))
    report={'date':'2026-10-17','development_head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
        'implementation_hashes':{str(p.relative_to(ROOT)):sha(p.read_bytes()) for p in sorted((ROOT/'src/ohscanner/detectors/data').glob('*.py'))},
        'model_sha256':sha((ROOT/'src/ohscanner/detectors/data/historical_profiles.json').read_bytes()),
        'runs':results,'holdout_executed':False,'runtime_poc_executed':False,'validated_vulnerability':0}
    digest=save(args.output_dir/'D3_REAL_SCAN.json',report)
    save(HERE/'D3_REAL_SCAN.json',report)
    print(json.dumps({'report_sha256':digest,'runs':[{k:r[k] for k in ('name','commit','public_candidate_count','public_coverage','private_candidate_count','public_repeat_equal','private_repeat_equal')} for r in results]},indent=2))
if __name__=='__main__':main()
