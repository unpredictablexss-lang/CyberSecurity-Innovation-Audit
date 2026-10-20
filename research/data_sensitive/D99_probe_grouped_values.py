"""D99 frozen grouped-label/value-return effects and caller-flow controls."""
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

REVISIONS=('4bff1ae5f2e5d955104e58dfd2feb7248bddfb7d',
           'f9296a695907845e6bd32598892ff036d4ac62d1')
CASES={
    'grouped_bare':'case 0:case 1:return;default:return;',
    'shared_default':'case 0:default:return;case 7:return;',
    'multiple_groups':'case 0:case 1:return;case 2:case 3:return;default:return;',
    'literal_values':'case 0:return 0;default:return 7;',
    'unknown_call_value':'case 0:return Consume(key);default:return 0;',
    'real_log_value':'case 0:return(HILOG_INFO(1,"%{public}s",key),0);default:return 0;',
    'material_return_helper':'',
    'empty_tail_live':'case 0:return;default:',
    'group_break_live':'case 0:case 1:break;default:return;',
    'executable_fallthrough_live':'case 0:*p=7;case 1:break;default:return;',
    'missing_default':'case 0:case 1:return;',
    'duplicate_label':'case 0:case 0:return;default:return;',
    'noncanonical_label':'case 0x0:case 1:return;default:return;',
    'partial_header':'case 0:case 1:return;default:return;',
    'macro_context':'case 0:case 1:return;default:return;',
    'unsupported_lambda':'case 0:return [](){return 0;}();default:return 0;',
    'goto_live_label':'case 0:case 1:return;default:return;',
}


def source(case):
    if case=='material_return_helper':
        return '\n'.join(('const char*Select(const char*value,int selector){',
            'switch(selector){case 0:case 1:return value;default:return(value);}}',
            'void Callback(const char*key,int selector){',
            'const char*output=Select(key,selector);',
            'HILOG_INFO(1,"%{public}s",output);','}'))
    prefix=('#define UNKNOWN_CONTEXT 1' if case=='macro_context' else
            'unsigned Consume(const char*);' if case=='unknown_call_value' else '')
    result='unsigned' if case in ('literal_values','unknown_call_value','real_log_value','unsupported_lambda') else 'void'
    before='if(selector==3){goto output;}' if case=='goto_live_label' else ''
    write=('output: ' if case=='goto_live_label' else '')+'*p=(unsigned char)key[0];'
    return '\n'.join((prefix,result+' Callback(const char*key,int selector){',
        'unsigned first=0;unsigned*p=&first;',before,
        'switch(selector){'+CASES[case]+'}',write,
        'HILOG_INFO(1,"%{public}u",first);',
        'return 9;' if result!='void' else '', '}'))


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--worker');parser.add_argument('--case')
    parser.add_argument('--output',default='D:/openHarmonyScanner/outputs/D99_GROUPED_VALUES_20261020.json')
    args=parser.parse_args()
    if args.worker:
        # Reuse the explicit Callback source model and selected partial-header
        # worker, changing only the synthetic source generated for this slice.
        support.source=source
        print(json.dumps(support.worker(args.worker,args.case),ensure_ascii=False));return
    result={'schema':1,'study':'D99 grouped return syntax and preserved return-value/effect dependencies',
            'cases':{k:{'source':source(k),'sha256':hashlib.sha256(source(k).encode()).hexdigest()}
                     for k in CASES},'runs':[]}
    for revision in REVISIONS:
        raw=subprocess.check_output(['git','archive',revision,'src/'],cwd=support.support.REPO)
        snapshot=Path('D:/openHarmonyScanner/records/D99_grouped_values_20261020')/revision
        snapshot.mkdir(parents=True,exist_ok=True)
        with tarfile.open(fileobj=io.BytesIO(raw)) as tar:tar.extractall(snapshot,filter='data')
        runs={k:json.loads(subprocess.check_output([sys.executable,'-B',str(Path(__file__).resolve()),
              '--worker',str(snapshot),'--case',k],cwd=snapshot)) for k in CASES}
        result['runs'].append({'revision':revision,'src_archive_sha256':hashlib.sha256(raw).hexdigest(),'cases':runs})
        print(revision[:8],{k:[f['line'] for f in v['direct']['findings']] for k,v in runs.items()})
    output=Path(args.output);output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')


if __name__=='__main__':main()
