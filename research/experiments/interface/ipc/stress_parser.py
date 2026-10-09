"""Optional real-source detector stress; target source is never executed."""
import argparse,gc,hashlib
from pathlib import Path
from src.ohscanner.detectors.interface.analysis import Interpreter
from src.ohscanner.detectors.interface.models import IpcPolicy
from src.ohscanner.contracts import SourceUnit

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--workspace',type=Path,required=True);ap.add_argument('--rounds',type=int,default=3);args=ap.parse_args()
 base=args.workspace/'pairs';paths=sorted(base.rglob('*.cpp'))
 if not paths:raise ValueError('No source snapshots acquired')
 for i in range(args.rounds):
  for p in paths:
   raw=p.read_bytes();unit=SourceUnit(str(p.relative_to(base)),'cpp',raw.decode(),hashlib.sha256(raw).hexdigest(),'partial')
   analysis=Interpreter((unit,),IpcPolicy());analysis.run();del analysis;gc.collect()
  print('round',i,'files',len(paths),flush=True)
if __name__=='__main__':main()
