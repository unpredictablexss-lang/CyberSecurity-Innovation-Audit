"""Frozen source, fresh-process D96 condition/header pointer-scope controls."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile

sys.path.insert(0,str(Path(__file__).resolve().parent))
import D95_probe_loop_scope as support

REVISIONS=('9c298fefee8612cb7b00e2657db0e7b5d1c500e8',
           'a3d414b600d18aab886a22876669f1d043a98f2f')
HEADERS={
    'if_initializer':'if(unsigned*p=&inner;flag){*p=(unsigned char)key[0];}',
    'if_declaration':'if(unsigned*p=&inner){*p=(unsigned char)key[0];}',
    'while_declaration':'while(unsigned*p=&inner){*p=(unsigned char)key[0];break;}',
    'switch_initializer':'switch(unsigned*p=&inner;flag){case 0:*p=(unsigned char)key[0];break;}',
    'if_restore':'if(unsigned*p=&inner;flag){}',
    'while_restore':'while(unsigned*p=&inner){break;}',
    'switch_restore':'switch(unsigned*p=&inner;flag){default:break;}',
    'literal_only':'if(unsigned*p=&inner;flag){*p=7;}',
    'unknown_destination':'if(unsigned*p=GetDestination();flag){*p=(unsigned char)key[0];}',
}


def source(case):
    tail='*p=(unsigned char)key[0];' if case.endswith('_restore') else ''
    return '\n'.join(('void Callback(const char*key,bool flag){',
        'unsigned outer=0,inner=0;unsigned*p=&outer;',HEADERS[case],tail,
        'HILOG_INFO(1,"%{public}u",inner);',
        'HILOG_INFO(1,"%{public}u",outer);','}'))


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--worker');parser.add_argument('--case')
    parser.add_argument('--output',default='D:/openHarmonyScanner/outputs/D96_CONDITION_SCOPE_20261020.json')
    args=parser.parse_args()
    if args.worker:
        support.SOURCE=source(args.case)
        print(json.dumps(support.worker(args.worker),ensure_ascii=False));return
    result={'schema':1,'study':'D96 scoped condition declarations; explicit synthetic source model',
            'cases':{k:{'source':source(k),'sha256':hashlib.sha256(source(k).encode()).hexdigest()}
                     for k in HEADERS},'runs':[]}
    for revision in REVISIONS:
        raw=subprocess.check_output(['git','archive',revision,'src/'],cwd=support.REPO)
        snapshot=Path('D:/openHarmonyScanner/records/D96_condition_scope_20261020')/revision
        snapshot.mkdir(parents=True,exist_ok=True)
        with tarfile.open(fileobj=io.BytesIO(raw)) as tar:tar.extractall(snapshot,filter='data')
        runs={k:json.loads(subprocess.check_output([sys.executable,'-B',str(Path(__file__).resolve()),
              '--worker',str(snapshot),'--case',k],cwd=snapshot)) for k in HEADERS}
        result['runs'].append({'revision':revision,'src_archive_sha256':hashlib.sha256(raw).hexdigest(),'cases':runs})
        print(revision[:8],{k:[f['line'] for f in v['direct']['findings']] for k,v in runs.items()})
    output=Path(args.output);output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')


if __name__=='__main__':main()
