from __future__ import annotations
import argparse, json, sys
from pathlib import Path

class DuplicateKey(ValueError): pass

def unique_pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise DuplicateKey(f'duplicate JSON key: {key}')
        out[key] = value
    return out

def load(path: Path):
    return json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=unique_pairs)

def normalized_issues(row):
    result=[]
    for item in row.get('issues', []):
        result.append(json.loads(item) if isinstance(item, str) else item)
    return sorted(result, key=lambda x:(x.get('start_line',-1),x.get('end_line',-1),x.get('kind','')))

def main():
    ap=argparse.ArgumentParser(description='Replay D79 D52 parse-coverage crosswalk against frozen D50/D67/D68/D74 evidence.')
    ap.add_argument('--d50',type=Path,required=True)
    ap.add_argument('--d67',type=Path,required=True)
    ap.add_argument('--d68',type=Path,required=True)
    ap.add_argument('--d74',type=Path,required=True)
    ap.add_argument('--expected',type=Path,default=Path(__file__).with_name('D79_D52_GET_PASTE_DATA_PARSE_COVERAGE_20261026.json'))
    args=ap.parse_args()
    e50,e67,e68,e74,expected=map(load,[args.d50,args.d67,args.d68,args.d74,args.expected])
    src=expected['source']
    for label,doc in [('D50',e50),('D68',e68)]:
        assert doc['repository']==src['repository'], f'{label}: repository mismatch'
        assert doc['commit']==src['commit'], f'{label}: source commit mismatch'
        assert doc['git_tree']==src['tree'], f'{label}: source tree mismatch'
    assert e67['source']['commit']==src['commit'] and e67['source']['tree']==src['tree']
    assert e74['repos']['D52_historical']['commit']==src['commit'] and e74['repos']['D52_historical']['tree']==src['tree']
    rows67={r['file']:r for r in e67['files']}
    rows50={r['file']:r for r in e50['detector_runs'][0]['parsing']}
    rows68={r['file']:r for r in e68['detector_runs'][0]['parsing']}
    rows74={r['path']:r for r in e74['repos']['D52_historical']['evidence']}
    checked=0
    for route in expected['route_rows']:
        path=route['path']; assert path in rows67 and path in rows50 and path in rows68, f'missing parse row: {path}'
        assert rows67[path]['source_sha256']==route['source_sha256'], f'D67 source hash mismatch: {path}'
        assert rows50[path]['status']==route['D50_historical']['status'], f'D50 status mismatch: {path}'
        assert normalized_issues(rows50[path])==route['D50_historical']['issues'], f'D50 issues mismatch: {path}'
        assert rows68[path]['status']==route['D68_current_runtime']['status'], f'D68 status mismatch: {path}'
        assert normalized_issues(rows68[path])==route['D68_current_runtime']['issues'], f'D68 issues mismatch: {path}'
        if path in rows74:
            assert rows74[path]['sha256']==route['source_sha256'], f'D74 SHA mismatch: {path}'
            if route.get('blob_oid'):
                assert rows74[path]['blob_oid']==route['blob_oid'], f'D74 blob mismatch: {path}'
        checked+=1
    by={r['path']:r for r in expected['route_rows']}
    assert by['services/zidl/src/pasteboard_service_stub.cpp']['D50_historical']['issues']==[{'end_line':58,'kind':'error','start_line':58}]
    assert by['services/zidl/src/pasteboard_service_stub.cpp']['D68_current_runtime']['status']=='complete'
    assert by['services/zidl/include/pasteboard_service_stub.h']['D50_historical']['issues']==[{'end_line':35,'kind':'missing','start_line':35}]
    assert by['services/core/include/i_pasteboard_service.h']['D50_historical']['issues']==[{'end_line':43,'kind':'error','start_line':43}]
    print(f'D79 replay PASS: {checked} route rows; source binding, D50/D68 parse status/issues, and available D74 SHA/blob bindings match.')
    print('Interpretation remains source-only; D50 stub.cpp ERROR:58 intersects actual member-pointer dispatch expression.')

if __name__=='__main__':
    try: main()
    except Exception as exc:
        print(f'D79 replay FAIL: {type(exc).__name__}: {exc}',file=sys.stderr); raise
