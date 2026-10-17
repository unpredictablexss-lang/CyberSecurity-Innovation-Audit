"""D2 research-only coverage audit; never changes public AST admission."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from types import ModuleType
from src.ohscanner.indexing import prepare_git_context, environment_fingerprint
from src.ohscanner.execution import run_reviewed_detectors
from src.ohscanner.runner import DetectorRegistry
from src.ohscanner.detectors.data.models import DEFAULT_SOURCE, SOURCE_MODEL_VERSION
from src.ohscanner.detectors.data.sensitive_exposure import SensitiveExposureDetector, LocalFlow, walk

D1='f11d5fdf4ab01a345a1ffb702b18edb6b5109a38'
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]

def digest(data):return hashlib.sha256(data).hexdigest()
def public(repo, includes, detector):
    registry=DetectorRegistry();registry.register(detector)
    return run_reviewed_detectors(repo,DEFAULT_SOURCE.repository,DEFAULT_SOURCE.commit,includes,registry)

def run(repo,out):
    manifest=json.loads((HERE/'source_manifest.json').read_text())
    selected=[r for r in manifest if r['repository']==DEFAULT_SOURCE.repository and r['file'].endswith(('.c','.cpp','.h'))]
    includes=tuple(r['file'] for r in selected)
    assert len(includes)==9
    context,tree,inventory,parsing,sources=prepare_git_context(repo,DEFAULT_SOURCE.repository,DEFAULT_SOURCE.commit,includes)
    for row,source in zip(sorted(selected,key=lambda r:r['file']),sources):
        assert row['file']==source.path and row['blob']==source.oid and row['sha256']==digest(source.data)
    old_source=subprocess.check_output(['git','show',D1+':src/ohscanner/detectors/data/sensitive_exposure.py'],cwd=ROOT).decode()
    module=ModuleType('src.ohscanner.detectors.data._d1_research')
    module.__package__='src.ohscanner.detectors.data';sys.modules[module.__name__]=module
    exec(compile(old_source,'D1-reviewed-detector','exec'),module.__dict__)
    baseline=public(repo,includes,module.SensitiveExposureDetector())
    first=public(repo,includes,SensitiveExposureDetector());second=public(repo,includes,SensitiveExposureDetector())
    def observations(report):
        return [(x['file'],x['line'],x['rule_id'],x['source_sha256'],x['message']) for run in report['detector_runs'] for x in run['diagnostics']]
    assert observations(first)==observations(second) and first['detector_coverage']==second['detector_coverage']
    assert baseline['snapshot_sha256']==first['snapshot_sha256']==second['snapshot_sha256']
    coverage=first['detector_coverage']['detectors'][SensitiveExposureDetector.detector_id]
    outcomes={p:'complete' for p in coverage['analyzed_files']}
    outcomes.update({p:'partial' for p in coverage['partially_inspected_files']})
    outcomes.update({x['file']:x['analysis_status'] for x in coverage['unexamined']})
    rows=[]
    for unit,source in zip(context.units,sources):
        probe=LocalFlow(unit,DEFAULT_SOURCE);findings=probe.run()
        nodes=[];pending=[probe.tree.root_node]
        while pending:
            node=pending.pop();nodes.append(node);pending.extend(reversed(node.children))
        errors=[{'type':n.type,'missing':n.is_missing,'start_line':n.start_point[0]+1,'end_line':n.end_point[0]+1,'parent_type':n.parent.type if n.parent else None} for n in nodes if n.is_error or n.is_missing]
        probe_sources=list({(x['line'],x['description']):x for x in probe.source_sites}.values())
        probe_sinks=list({(x['line'],x['symbol']):x for x in probe.sink_sites}.values())
        rows.append({'file':unit.path,'blob':source.oid,'sha256':unit.sha256,'ast_status':unit.parse_status,
                     'production_outcome':outcomes[unit.path],'parse_issues':unit.parse_issues,
                     'parser_error_regions':errors,
                     'private_probe_only':True,'probe_not_production_eligible_override':True,
                     'probe_candidate_count':len(findings),'source_sites':probe_sources,'sink_sites':probe_sinks,
                     'functions':probe.function_audits,'model_limitations':sorted(probe.gaps),
                     'potential_benefit':'Only error-free local syntax may be considered after owner review; include/build/binding remain unknown.'})
    counts={k:sum(x['production_outcome']==k for x in rows) for k in ('complete','partial','not_analyzed','failed')}
    assert sum(counts.values())==9
    hashes={};out.mkdir(parents=True,exist_ok=True)
    for name,data in [('d1.json',baseline),('d2-first.json',first),('d2-second.json',second)]:
        b=(json.dumps(data,ensure_ascii=False,indent=2)+'\n').encode();(out/name).write_bytes(b);hashes[name]=digest(b)
    report={'source_repository':DEFAULT_SOURCE.repository,'source_commit':DEFAULT_SOURCE.commit,'source_tree':tree,
            'snapshot_sha256':first['snapshot_sha256'],'scope_paths':includes,'source_model_version':SOURCE_MODEL_VERSION,
            'detector_versions':{'baseline':module.SensitiveExposureDetector.version,'current':SensitiveExposureDetector.version},
            'development_head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
            'implementation_sha256':digest((ROOT/'src/ohscanner/detectors/data/sensitive_exposure.py').read_bytes()),
            'model_file_sha256':digest((ROOT/'src/ohscanner/detectors/data/models.py').read_bytes()),
            'runner_sha256':digest((ROOT/'src/ohscanner/runner.py').read_bytes()),'environment':environment_fingerprint(),
            'public_coverage_counts':counts,'d1_candidates':len(observations(baseline)),'d2_candidates':len(observations(first)),
            'coverage_changed':baseline['detector_coverage']['detectors'][SensitiveExposureDetector.detector_id]['coverage_counts']!=counts,
            'algorithm_changed':True,'scope_and_model_semantics_changed':False,'d2_repeat_equal':True,
            'report_sha256':hashes,'files':rows,'validated_vulnerability':0,
            'limitations':['Private probe is not production scanning and does not override Runner.',
                           'No accuracy/safety conclusion from zero findings or counts.']}
    (out/'coverage.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    (HERE/'D2_COVERAGE.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k not in ('files','environment','scope_paths')},indent=2))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--repo-dir',type=Path,required=True);p.add_argument('--output-dir',type=Path,required=True)
    a=p.parse_args();run(a.repo_dir,a.output_dir)
