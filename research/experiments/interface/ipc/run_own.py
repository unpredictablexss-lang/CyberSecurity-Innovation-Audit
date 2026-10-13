"""Reproduce the IPC plugin through the existing fixed-Git execution chain."""
import argparse,hashlib,json,time
from pathlib import Path
from src.ohscanner.detectors.interface.detector import IpcInterfaceDetector
from src.ohscanner.execution import run_reviewed_detectors
from src.ohscanner.runner import DetectorRegistry

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--workspace',type=Path,required=True);a=ap.parse_args()
 project=Path(__file__).resolve().parents[4];metadata=project/'research/corpus/interface/ipc/verified_pairs.jsonl'
 rows=[];outdir=a.workspace/'artifacts/own';outdir.mkdir(exist_ok=True)
 for line in metadata.read_text().splitlines():
  sample=json.loads(line)
  for revision in ('vulnerable','fixed'):
   scope=tuple(sorted(f['path'] for f in sample['source_files'] if f['revision']==revision and f['path'].endswith('.cpp') and '/test/' not in f['path'] and '/unittest/' not in f['path']))
   registry=DetectorRegistry();registry.register(IpcInterfaceDetector());start=time.monotonic()
   report=run_reviewed_detectors(a.workspace/'repos'/sample['repository'].split('/')[-1],sample['repository'],sample[revision+'_commit'],scope,registry)
   out=outdir/(sample['sample_id']+'-'+revision+'.json');out.write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n')
   diagnostics=report['detector_runs'][0]['diagnostics'];hits=[d for d in diagnostics if d['rule_id']==sample['expected_rule'] and d.get('symbol') in sample['affected_symbols']]
   record=dict(sample_id=sample['sample_id'],revision=revision,commit=sample[revision+'_commit'],family=sample['family'],expected_rule=sample['expected_rule'],root_candidates=len(hits),diagnostic_count=len(diagnostics),execution_status=report['detector_runs'][0]['status'],source_parsing=report['source_parsing'],source_scope=scope,elapsed_seconds=time.monotonic()-start,native_report=str(out),native_report_sha256=hashlib.sha256(out.read_bytes()).hexdigest(),hits=hits)
   rows.append(record);print(sample['sample_id'],revision,record['execution_status'],'root candidates',len(hits),flush=True)
 (a.workspace/'artifacts/own-runs.json').write_text(json.dumps(rows,indent=2)+'\n')
if __name__=='__main__':main()
