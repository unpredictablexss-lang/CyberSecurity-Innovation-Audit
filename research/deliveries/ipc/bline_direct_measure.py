"""Direct read-only measurement of the worktree IPC detector over pinned trees.

This bypasses the platform's M1 per-run file bound (git_source MAX_SOURCE_FILES)
the same way the pinned audit driver does: it enumerates the pinned tree itself
and feeds SourceUnits to the detector. It is NOT a production path and does not
write into any corpus clone. Two passes are recorded, matching the pinned driver:

  all-files     partial and complete parses, so recall is kept (run reports blocked)
  complete-ast  complete parses only, so the run completes

Candidate counts are per pass; a candidate seen in both is one interpretation.
"""
import argparse, collections, hashlib, json, os, subprocess, sys, time

WT = '/home/audit/ohscanner/worktrees/parallel-ipc-20261017'
sys.path.insert(0, WT)

from src.parser.ast import parse_source
from src.ohscanner.contracts import SourceUnit, ScanContext, ScanRequest
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.detectors.interface.detector import IpcInterfaceDetector

EXCLUDED = {'test','tests','unittest','unittests','fuzztest','fuzz','mock','mocks',
            'sample','samples','example','examples','demo','demos','benchmark',
            'benchmarks','third_party','thirdparty','3rdparty'}
EXTS = {'.c':'c','.cc':'cpp','.cpp':'cpp','.cxx':'cpp','.h':'cpp','.hpp':'cpp',
        '.hh':'cpp','.hxx':'cpp','.inl':'cpp'}
MAX_BYTES = 4 * 1024 * 1024

def git(repo,*args,text=False):
    p=subprocess.run(['git','-C',repo,*args],capture_output=True,check=True)
    return p.stdout.decode('utf-8','replace') if text else p.stdout

def tree(repo,commit):
    out=[]
    for line in git(repo,'ls-tree','-r','-z',commit).decode('utf-8','replace').split(chr(0)):
        if not line: continue
        meta,path=line.split('\t',1)
        mode,kind,oid=meta.split()
        out.append((path,mode,kind,oid))
    return out

def eligible(path,mode,kind):
    if kind!='blob' or mode not in ('100644','100755'): return False,'entry_kind'
    ext=os.path.splitext(path)[1].lower()
    if ext not in EXTS: return False,'non_source'
    if any(seg in EXCLUDED for seg in path.split('/')[:-1]): return False,'excluded_pattern'
    return True,''

def run(repo,commit,repository,out_dir):
    counts=collections.Counter(); units=[]; skipped=[]
    for path,mode,kind,oid in tree(repo,commit):
        ok,why=eligible(path,mode,kind)
        if not ok:
            counts[why]+=1
            if len(skipped)<200: skipped.append({'file':path,'reason':why})
            continue
        data=git(repo,'cat-file','blob',oid)
        if len(data)>MAX_BYTES:
            counts['oversize']+=1; skipped.append({'file':path,'reason':'oversize'}); continue
        try: text=data.decode('utf-8')
        except UnicodeDecodeError:
            counts['non_utf8']+=1; skipped.append({'file':path,'reason':'non_utf8'}); continue
        lang=EXTS[os.path.splitext(path)[1].lower()]
        index=parse_source(text,language=lang)
        units.append(SourceUnit(path,lang,text,hashlib.sha256(data).hexdigest(),index.parse_status))
        counts['selected_files']+=1; counts['selected_bytes']+=len(data)
    def detect(pass_units):
        request=ScanRequest('ipc-direct',repository,commit,snapshot_digest(tuple(pass_units)),
                            'current-component:'+repository)
        ctx=ScanContext(request,tuple(pass_units),{'ast':{u.path:{} for u in pass_units}})
        det=IpcInterfaceDetector()
        started=time.time()
        result=det.detect(ctx,ctx.units)
        rules=collections.Counter(f.rule_id for f in result.findings)
        return {'status':result.status,'seconds':round(time.time()-started,1),
                'analyzed_files':len(result.analyzed_files),
                'rules':dict(sorted(rules.items())),'candidates':sum(rules.values()),
                'limitations':[l for l in result.limitations if 'Entry/dispatch coverage' in l]}, result
    all_summary,_=detect(units)
    complete=[u for u in units if u.parse_status=='complete']
    complete_summary,_=detect(complete)
    report={'repository':repository,'commit':commit,'out':out_dir,
            'passes':{'all-files':all_summary,'complete-ast':complete_summary},
            'parse':{'complete':len(complete),'partial':sum(1 for u in units if u.parse_status=='partial'),
                     'failed':sum(1 for u in units if u.parse_status not in ('complete','partial'))},
            'scope':{k:v for k,v in sorted(counts.items())},'skipped_examples':skipped[:50],
            'validated_vulnerability':0}
    return report

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--repo-dir',required=True); ap.add_argument('--repository',required=True)
    ap.add_argument('--commit',required=True); ap.add_argument('--out',required=True)
    a=ap.parse_args()
    os.makedirs(a.out,exist_ok=True)
    report=run(a.repo_dir,a.commit,a.repository,a.out)
    json.dump(report,open(os.path.join(a.out,'report.json'),'w'),indent=2)
    print(json.dumps({'repository':a.repository,'all':report['passes']['all-files'],
                      'complete':report['passes']['complete-ast'],'parse':report['parse']}))
if __name__=='__main__': main()
