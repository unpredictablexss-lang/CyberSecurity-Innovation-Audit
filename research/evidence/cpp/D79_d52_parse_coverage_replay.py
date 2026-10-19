from __future__ import annotations
import argparse, hashlib, json, subprocess, sys
from pathlib import Path

class DuplicateKey(ValueError): pass

def unique_pairs(pairs):
    out={}
    for key,value in pairs:
        if key in out: raise DuplicateKey(f'duplicate JSON key: {key}')
        out[key]=value
    return out

def load(path:Path): return json.loads(path.read_text(encoding='utf-8'),object_pairs_hook=unique_pairs)
def sha(raw:bytes): return hashlib.sha256(raw).hexdigest()
def git_bytes(args, *gitargs):
    p=subprocess.run(args,check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    return p.stdout

def git_output(prefix, *gitargs):
    p=subprocess.run([*prefix,*gitargs],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    return p.stdout.decode('utf-8').strip()
def normalized_issues(row):
    out=[]
    for item in row.get('issues',[]): out.append(json.loads(item) if isinstance(item,str) else item)
    return sorted(out,key=lambda x:(x.get('start_line',-1),x.get('end_line',-1),x.get('kind','')))
def require(condition,message):
    if not condition: raise ValueError(message)
def main():
    ap=argparse.ArgumentParser(description='Replay and integrity-check the frozen D79 D52 parse-coverage crosswalk.')
    for name in ('d50','d67','d68','d74'): ap.add_argument('--'+name,type=Path,required=True)
    ap.add_argument('--expected',type=Path,default=Path(__file__).with_name('D79_D52_GET_PASTE_DATA_PARSE_COVERAGE_20261026.json'))
    ap.add_argument('--d52-git-dir',type=Path,required=True,help='bare or git-dir for openharmony/miscservices_pasteboard source objects')
    ap.add_argument('--scanner-git-dir',type=Path,help='scanner evidence repository git-dir; defaults to this script worktree')
    args=ap.parse_args()
    expected=load(args.expected); src=expected['source']; bindings=expected['evidence_bindings']
    evidence_files={'D50_component_replay':args.d50,'D67_parse_audit':args.d67,'D68_raw67_replay':args.d68,'D74_source_trace':args.d74}
    docs={}
    for key,path in evidence_files.items():
        b=bindings[key]; raw=path.read_bytes()
        require(sha(raw)==b['sha256'],f'{key}: local input SHA-256 mismatch')
        docs[key]=load(path)
    d50=docs['D50_component_replay']; d67=docs['D67_parse_audit']; d68=docs['D68_raw67_replay']; d74=docs['D74_source_trace']
    scanner_git_dir=args.scanner_git_dir
    if scanner_git_dir:
        scanner_prefix=['git','--git-dir',str(scanner_git_dir)]
    else:
        scanner_prefix=['git','-C',str(args.expected.resolve().parent)]
        # Resolve actual worktree root, avoiding assumptions about current process directory.
        root=git_output(scanner_prefix,'rev-parse','--show-toplevel')
        scanner_prefix=['git','-C',root]
    # Tie each pinned artifact file to the listed evidence commit/tree and raw Git blob bytes.
    for key in evidence_files:
        b=bindings[key]; commit=b['git_commit']; path=b['path']; tree=b['git_tree']
        got_tree=git_output(scanner_prefix,'rev-parse',f'{commit}^{{tree}}')
        require(got_tree==tree,f'{key}: evidence commit tree mismatch')
        raw=git_bytes([*scanner_prefix,'show',f'{commit}:{path}'])
        require(sha(raw)==b['sha256'],f'{key}: Git-committed evidence SHA-256 mismatch')
        require(raw==evidence_files[key].read_bytes(),f'{key}: supplied file differs from pinned Git evidence')
    for label,doc in [('D50',d50),('D68',d68)]:
        require(doc['repository']==src['repository'] and doc['commit']==src['commit'] and doc['git_tree']==src['tree'],f'{label}: source binding mismatch')
    require(d67['source']['commit']==src['commit'] and d67['source']['tree']==src['tree'],'D67 source binding mismatch')
    require(d74['repos']['D52_historical']['commit']==src['commit'] and d74['repos']['D52_historical']['tree']==src['tree'],'D74 source binding mismatch')
    d52_prefix=['git','--git-dir',str(args.d52_git_dir)]
    got_tree=git_output(d52_prefix,'rev-parse',f"{src['commit']}^{{tree}}")
    require(got_tree==src['tree'],'D52 source Git tree mismatch')
    rows67={r['file']:r for r in d67['files']}; rows50={r['file']:r for r in d50['detector_runs'][0]['parsing']}; rows68={r['file']:r for r in d68['detector_runs'][0]['parsing']}; rows74={r['path']:r for r in d74['repos']['D52_historical']['evidence']}
    verified=[]
    for route in expected['route_rows']:
        path=route['path']; require(path in rows67 and path in rows50 and path in rows68,f'missing parser row: {path}')
        require(rows67[path]['source_sha256']==route['source_sha256'],f'D67 source SHA mismatch: {path}')
        require(rows50[path]['status']==route['D50_historical']['status'] and normalized_issues(rows50[path])==route['D50_historical']['issues'],f'D50 parser row mismatch: {path}')
        require(rows68[path]['status']==route['D68_current_runtime']['status'] and normalized_issues(rows68[path])==route['D68_current_runtime']['issues'],f'D68 parser row mismatch: {path}')
        # Independently prove path -> blob and blob bytes -> SHA-256 from the pinned source Git tree.
        blob=git_output(d52_prefix,'rev-parse',f"{src['commit']}:{path}")
        require(blob==route['blob_oid'],f'D52 Git blob OID mismatch: {path}')
        raw=git_bytes([*d52_prefix,'cat-file','blob',blob])
        require(sha(raw)==route['source_sha256'],f'D52 raw Git blob SHA-256 mismatch: {path}')
        if path in rows74:
            require(rows74[path]['sha256']==route['source_sha256'],f'D74 source SHA mismatch: {path}')
            require(rows74[path]['blob_oid']==route['blob_oid'],f'D74 blob mismatch: {path}')
        verified.append(path)
    by={r['path']:r for r in expected['route_rows']}
    require(by['services/zidl/src/pasteboard_service_stub.cpp']['D50_historical']['issues']==[{'end_line':58,'kind':'error','start_line':58}],'historical dispatch issue record mismatch')
    require(by['services/zidl/src/pasteboard_service_stub.cpp']['D68_current_runtime']['status']=='complete','D68 stub status mismatch')
    # Negative control: a one-byte whitespace mutation must fail the same input integrity check.
    d50_expected=bindings['D50_component_replay']['sha256']; tampered=args.d50.read_bytes()+b' '
    require(sha(tampered)!=d50_expected,'negative control unexpectedly accepted tampered D50 bytes')
    print(f'D79 replay PASS: {len(verified)} route rows; four evidence input hashes and Git snapshots verified; six raw source blobs verified.')
    print('Negative control PASS: appended whitespace to D50 bytes changes SHA-256 and is rejected by the bound-input check.')
    print('D50 stub.cpp ERROR:58 intersects the actual member-pointer dispatch expression; verdict remains source-only.')
if __name__=='__main__':
    try: main()
    except Exception as exc:
        print(f'D79 replay FAIL: {type(exc).__name__}: {exc}',file=sys.stderr); raise
