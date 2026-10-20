"""D98 frozen source observations of exact all-return switch termination."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile

sys.path.insert(0,str(Path(__file__).resolve().parent))
import D97_probe_switch_join as support

REVISIONS=('27301e6d824a107cb219b84a6b4e2a6f05266ab5',
           'b3dfd70894290c344017c33198b905c70eb51985')
CASES={
    'two_flat_returns':'case 0:return;default:return;',
    'three_flat_returns':'default:return;case 0:return;case 2:return;',
    'initializer_returns':'case 0:return;default:return;',
    'pre_switch_real_log':'case 0:return;default:return;',
    'missing_default':'case 0:return;',
    'mixed_break_return':'case 0:return;default:break;',
    'duplicate_case':'case 0:return;case 0:return;default:return;',
    'unknown_label':'case Unknown:return;default:return;',
    'grouped_fallthrough_gap':'case 0:default:return;',
    'return_expression_gap':'case 0:return LeakKey(key);default:return;',
    'macro_context':'case 0:return;default:return;',
    'partial_header':'case 0:return;default:return;',
    'goto_live_label':'case 0:return;default:return;',
    'nonidentifier_selector':'case 0:return;default:return;',
}


def source(case):
    prefix=('#define UNKNOWN_CONTEXT 1' if case=='macro_context' else
            'void LeakKey(const char*);' if case=='return_expression_gap' else
            'int GetSelector(const char*);' if case=='nonidentifier_selector' else '')
    before=('HILOG_INFO(1,"%{public}s",key);' if case=='pre_switch_real_log' else
            'if(selector==3){goto output;}' if case=='goto_live_label' else '')
    selector=('unsigned*q=&first;selector' if case=='initializer_returns' else
              'GetSelector(key)' if case=='nonidentifier_selector' else 'selector')
    write=('output: ' if case=='goto_live_label' else '')+'*p=(unsigned char)key[0];'
    return '\n'.join((prefix,'void Callback(const char*key,int selector){',
        'unsigned first=0;unsigned*p=&first;',before,
        'switch('+selector+'){'+CASES[case]+'}',write,
        'HILOG_INFO(1,"%{public}u",first);','}'))


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--worker');parser.add_argument('--case')
    parser.add_argument('--output',default='D:/openHarmonyScanner/outputs/D98_SWITCH_RETURNS_20261020.json')
    args=parser.parse_args()
    if args.worker:
        # The previous worker builds the same explicit synthetic Callback model
        # and, for partial_header, includes the extra selected malformed unit.
        support.source=source
        print(json.dumps(support.worker(args.worker,args.case),ensure_ascii=False));return
    result={'schema':1,'study':'D98 exact flat void-return switch liveness',
            'cases':{k:{'source':source(k),'sha256':hashlib.sha256(source(k).encode()).hexdigest(),
                        'outside_proof':k.endswith('_gap')} for k in CASES},'runs':[]}
    for revision in REVISIONS:
        raw=subprocess.check_output(['git','archive',revision,'src/'],cwd=support.support.REPO)
        snapshot=Path('D:/openHarmonyScanner/records/D98_switch_returns_20261020')/revision
        snapshot.mkdir(parents=True,exist_ok=True)
        with tarfile.open(fileobj=io.BytesIO(raw)) as tar:tar.extractall(snapshot,filter='data')
        runs={k:json.loads(subprocess.check_output([sys.executable,'-B',str(Path(__file__).resolve()),
              '--worker',str(snapshot),'--case',k],cwd=snapshot)) for k in CASES}
        result['runs'].append({'revision':revision,'src_archive_sha256':hashlib.sha256(raw).hexdigest(),'cases':runs})
        print(revision[:8],{k:[f['line'] for f in v['direct']['findings']] for k,v in runs.items()})
    output=Path(args.output);output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')


if __name__=='__main__':main()
