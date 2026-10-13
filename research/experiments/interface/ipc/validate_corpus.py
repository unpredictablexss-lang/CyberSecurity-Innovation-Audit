"""Validate fixed-source corpus without network or executing target code."""
import argparse,hashlib,json,subprocess
from pathlib import Path

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--workspace',required=True,type=Path);a=ap.parse_args()
 b=Path(__file__).resolve().parents[4];root=b/'research/corpus/interface/ipc';seen=set();files=0
 for name in ('verified_pairs.jsonl','pending_pairs.jsonl'):
  for line in (root/name).read_text().splitlines():
   s=json.loads(line);key=s['root_cause_instance_id'];assert key not in seen,key;seen.add(key)
   assert s['validated_vulnerability']==0 and s['runtime_validation']=='not_run'
   for f in s['source_files']:
    p=a.workspace/'pairs'/s['sample_id']/f['revision']/f['path'];raw=p.read_bytes()
    assert hashlib.sha256(raw).hexdigest()==f['sha256'],str(p)
    oid=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest();assert oid==f['git_blob'],str(p)
    assert f['commit']==s[f['revision']+'_commit'];assert len(f['commit'])==40
    files+=1
 freeze=json.loads((root/'design_freeze.json').read_text())
 for name,digest in freeze['source_sha256'].items():assert hashlib.sha256((b/name).read_bytes()).hexdigest()==digest,name
 print(json.dumps({'root_instances':len(seen),'verified_source_files':files,'frozen_detector_hashes':'match'}))
if __name__=='__main__':main()
