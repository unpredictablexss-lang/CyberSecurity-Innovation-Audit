"""Replay recorded baseline commands into a fresh workspace/artifact directory.
Default is plan-only: overwrite requires explicit --execute and existing databases
must be moved manually. Commands are argv arrays, never shell strings.
"""
import argparse,json,os,subprocess
from pathlib import Path

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--workspace',required=True,type=Path);ap.add_argument('--tool',choices=['joern','codeql','clang'],required=True);ap.add_argument('--execute',action='store_true');a=ap.parse_args()
 env=dict(os.environ);jdk=next((a.workspace/'tools').glob('jdk-21*'));env['JAVA_HOME']=str(jdk);env['PATH']=str(jdk/'bin')+':'+env['PATH']
 runs=json.loads((a.workspace/'artifacts'/(a.tool+'-runs.json')).read_text())
 for r in runs:
  commands=r.get('commands') or ([r['parse_command'],r['query_command']] if 'parse_command' in r else [r['command']])
  for i,cmd in enumerate(commands):
   print(json.dumps(cmd))
   if a.execute:
    out=a.workspace/'artifacts'/('replay-'+a.tool+'-'+str(r.get('unit','unit'))+'-'+str(i)+'.log')
    with out.open('wb') as f:subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT,env=env,timeout=600,check=True)
if __name__=='__main__':main()
