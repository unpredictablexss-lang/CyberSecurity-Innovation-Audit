"""Download passive pinned source snapshots; verify before atomically retaining them.
No checkout, build, target execution or exploit payload. Optional --git-objects
populates existing component clones for OHScanner's fixed-Git reader.
"""
import argparse,hashlib,json,subprocess,urllib.request
from pathlib import Path

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--workspace',type=Path,required=True);ap.add_argument('--git-objects',action='store_true');a=ap.parse_args()
 b=Path(__file__).resolve().parents[4]
 for name in ('verified_pairs.jsonl','pending_pairs.jsonl'):
  for line in (b/'research/corpus/interface/ipc'/name).read_text().splitlines():
   s=json.loads(line)
   for f in s['source_files']:
    p=a.workspace/'pairs'/s['sample_id']/f['revision']/f['path'];p.parent.mkdir(parents=True,exist_ok=True)
    if p.exists():raw=p.read_bytes()
    else:
     with urllib.request.urlopen(f['source_url'],timeout=60) as response:raw=response.read()
    assert hashlib.sha256(raw).hexdigest()==f['sha256'],str(p)
    assert hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==f['git_blob']
    p.write_bytes(raw)
    if a.git_objects:
     repo=a.workspace/'repos'/s['repository'].split('/')[-1]
     cp=subprocess.run(['git','-C',str(repo),'hash-object','-w','--stdin'],input=raw,capture_output=True,check=True)
     assert cp.stdout.decode().strip()==f['git_blob']
 print('Pinned files verified. Clone/fetch exact commits separately before --git-objects or run_own.')
if __name__=='__main__':main()
