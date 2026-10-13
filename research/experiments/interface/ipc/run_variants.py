"""Reproduce authored/generated controls and catalog/summary ablations."""
import argparse,hashlib,json
from dataclasses import replace
from pathlib import Path
from src.parser.ast import parse_source
from src.ohscanner.contracts import SourceUnit,ScanContext,ScanRequest
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.detectors.interface.detector import IpcInterfaceDetector
from src.ohscanner.detectors.interface.models import IpcPolicy

def detect(text,policy):
 index=parse_source(text,language='cpp');u=SourceUnit('sample.cpp','cpp',text,hashlib.sha256(text.encode()).hexdigest(),index.parse_status)
 request=ScanRequest('ipc-test','fixture/ipc','synthetic-ipc-v1',snapshot_digest((u,)),'current-component:fixture/ipc')
 context=ScanContext(request,(u,),{'ast':{'sample.cpp':index.to_dict()}})
 run=IpcInterfaceDetector(policy).detect(context,context.units)
 return sorted({f.rule_id for f in run.findings}),run.status

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--workspace',type=Path,required=True);a=ap.parse_args();b=Path(__file__).resolve().parents[4];base=b/'tests/fixtures/ipc';p=IpcPolicy()
 profiles={'full':p,'no-local-call-summary':replace(p,max_call_depth=0),'no-caller-provenance':replace(p,caller_token_calls=frozenset(),caller_uid_calls=frozenset()),'no-sensitive-api-catalog':replace(p,sensitive_calls=frozenset(),object_sensitive_calls=frozenset(),caller_class_sensitive_calls=frozenset())}
 rows=[]
 for profile,policy in profiles.items():
  for s in json.loads((base/'manifest.json').read_text()):
   rules,status=detect((base/s['file']).read_text(),policy);expected=s['expected_rule']
   rows.append(dict(profile=profile,sample_id=s['sample_id'],family=s['family'],expected_rule=expected,reported_rules=rules,expectation_met=(expected in rules if expected else not rules),execution_status=status))
 (a.workspace/'artifacts/ablation-results.json').write_text(json.dumps(rows,indent=2)+'\n')
 rows=[]
 for s in json.loads((b/'research/corpus/interface/ipc/generated_holdout.json').read_text()):
  rules,status=detect(s['text'],p);expected=s['expected_rule'];rows.append(dict(sample_id=s['sample_id'],family=s['family'],expected_rule=expected,reported_rules=rules,expectation_met=(expected in rules if expected else not rules),execution_status=status))
 (a.workspace/'artifacts/generated-holdout-results.json').write_text(json.dumps(rows,indent=2)+'\n')
 print('Generated controls',sum(x['expectation_met'] for x in rows),'/',len(rows))
if __name__=='__main__':main()
