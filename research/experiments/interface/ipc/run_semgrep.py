"""Run OSS native engine per source file; retain failures and raw reports."""
import argparse,hashlib,json,subprocess,time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--workspace',type=Path,required=True);a=ap.parse_args()
 project=Path(__file__).resolve().parents[4];root=a.workspace
 core=next((root/'tools/semgrep-native').rglob('semgrep-core'));rules=Path(__file__).with_name('semgrep-rules.json')
 jobs=[('synthetic',p) for p in sorted((project/'tests/fixtures/ipc').glob('*.cpp'))]
 jobs += [(pair.name+'-'+rev,p) for pair in sorted((root/'pairs').iterdir()) for rev in ('vulnerable','fixed') for p in sorted((pair/rev).rglob('*.cpp')) if '/test/' not in str(p) and '/unittest/' not in str(p)]
 outdir=root/'artifacts/semgrep-files';outdir.mkdir(exist_ok=True)
 def one(job):
  unit,p=job;key=hashlib.sha256(str(p).encode()).hexdigest()[:16];out=outdir/(key+'.json');log=outdir/(key+'.stderr.log');cmd=[str(core),'-rules',str(rules),'-lang','cpp','-json_nodots','-j','1',str(p)];start=time.monotonic()
  code=None;error=None
  try:
   with out.open('w') as f,log.open('w') as e:code=subprocess.run(cmd,stdout=f,stderr=e,timeout=60).returncode
  except subprocess.TimeoutExpired:error='timeout'
  try:data=json.loads(out.read_text());matches=data.get('results',[]);errors=data.get('errors',[])
  except (ValueError,FileNotFoundError):matches=[];errors=['invalid/missing native JSON']
  return dict(unit=unit,file=str(p),tool='semgrep-core',tool_version='1.180.0',command=cmd,exit=code,error=error,elapsed_seconds=time.monotonic()-start,source_sha256=hashlib.sha256(p.read_bytes()).hexdigest(),ruleset_sha256=hashlib.sha256(rules.read_bytes()).hexdigest(),native_report=str(out),native_report_sha256=hashlib.sha256(out.read_bytes()).hexdigest() if out.exists() else None,analyzed_files=data.get('paths',{}).get('scanned',[]) if 'data' in locals() else [],matches=matches,errors=errors)
 with ThreadPoolExecutor(max_workers=3) as ex:results=list(ex.map(one,jobs))
 (root/'artifacts/semgrep-file-runs.json').write_text(json.dumps(results,indent=2)+'\n')
 print(json.dumps(dict(files=len(results),successful=sum(x['exit']==0 for x in results),matches=sum(len(x['matches']) for x in results),errors=sum(len(x['errors']) for x in results))))
if __name__=='__main__':main()
