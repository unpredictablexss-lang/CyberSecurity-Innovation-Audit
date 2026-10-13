"""Rebuild independent-TU synthetic baselines; refuses existing output prefix."""
import argparse,hashlib,json,os,subprocess,time
from pathlib import Path

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--workspace',type=Path,required=True);ap.add_argument('--prefix',default='synthetic-replay');a=ap.parse_args()
 if not a.prefix.replace('-','').replace('_','').isalnum():raise ValueError('Simple prefix required')
 b=Path(__file__).resolve().parents[4];tools=a.workspace/'tools';out=a.workspace/'artifacts';prefix=a.prefix
 targets=[out/(prefix+'.cpg'),out/(prefix+'-db'),out/(prefix+'.json'),out/(prefix+'.sarif')]
 if any(p.exists() for p in targets):raise FileExistsError('Choose new prefix; preserve prior outputs')
 jdk=next(tools.glob('jdk-21*'));env=dict(os.environ);env['JAVA_HOME']=str(jdk);env['PATH']=str(jdk/'bin')+':'+env['PATH']
 source=b/'tests/fixtures/ipc';query=Path(__file__).parent
 commands=[
 [str(tools/'joern-cli/joern-parse'),str(source),'--language','C','--output',str(targets[0]),'--frontend-args','--log-problems'],
 [str(tools/'joern-cli/joern'),'--script',str(query/'joern-ipc.sc'),'--param','cpgFile='+str(targets[0]),'--param','outFile='+str(targets[2])],
 [str(tools/'codeql/codeql'),'database','create',str(targets[1]),'--language=cpp','--build-mode=none','--source-root='+str(source),'--threads=1'],
 [str(tools/'codeql/codeql'),'database','analyze',str(targets[1]),str(query/'codeql'),'--format=sarif-latest','--output='+str(targets[3]),'--threads=1','--ram=2048']]
 rows=[]
 for i,cmd in enumerate(commands):
  log=out/(prefix+'-'+str(i)+'.log');t=time.monotonic()
  with log.open('wb') as f:cp=subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT,env=env,timeout=600)
  rows.append(dict(command=cmd,exit=cp.returncode,elapsed_seconds=time.monotonic()-t,log=str(log),log_sha256=hashlib.sha256(log.read_bytes()).hexdigest()))
  if cp.returncode:break
 (out/(prefix+'-runs.json')).write_text(json.dumps(rows,indent=2)+'\n')
 if any(r['exit'] for r in rows):raise SystemExit(1)
if __name__=='__main__':main()
