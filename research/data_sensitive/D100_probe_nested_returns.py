"""D100 finite nested-return controls and a separately recorded comma-value gap."""
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

REVISIONS=('d836b1c59cbe49f26fe4bdeb2ee5fb73e6a03498',
           '835f02dc72ac0c1926634e0cc4a10f82a4994052')
CASES={
    'bare_if':'case 0:if(flag)return;else return;default:return;',
    'block_if':'case 0:if(flag){return;}else{return;}default:return;',
    'group_if':'case 0:case 1:if(flag)return;else return;default:return;',
    'literal_returns':'case 0:if(flag)return 0;else return 1;default:return 2;',
    'condition_escape':'case 0:if(GetFlag(key))return;else return;default:return;',
    'return_escape':'case 0:if(flag)return Consume(key);else return 0;default:return 1;',
    'material_helper':'',
    'literal_helper':'',
    'real_pre_switch_log':'case 0:if(flag)return;else return;default:return;',
    'missing_else_live':'case 0:if(flag)return;default:return;',
    'mixed_break_live':'case 0:if(flag)return;else break;default:return;',
    'empty_branch_live':'case 0:if(flag){}else return;default:return;',
    'nested_switch':'case 0:if(flag){switch(selector){default:return;}}else return;default:return;',
    'nested_loop':'case 0:if(flag){while(flag){break;}}else return;default:return;',
    'macro_context':'case 0:if(flag)return;else return;default:return;',
    'partial_header':'case 0:if(flag)return;else return;default:return;',
    'goto_live_label':'case 0:if(flag)return;else return;default:return;',
    'comma_status_known_gap':'',
}


def source(case):
    if case=='material_helper':
        return '\n'.join(('const char*Choose(const char*value,int sel,bool flag){',
            'switch(sel){case 0:if(flag)return value;else return(value);default:return value;}}',
            'void Callback(const char*key,int selector,bool flag){',
            'const char*out=Choose(key,selector,flag);',
            'HILOG_INFO(1,"%{public}s",out);','}'))
    if case=='literal_helper':
        return '\n'.join(('unsigned Status(const char*value,int sel,bool flag){',
            'switch(sel){case 0:if(flag)return 0;else return 1;default:return 2;}}',
            'void Callback(const char*key,int selector,bool flag){',
            'unsigned code=Status(key,selector,flag);',
            'HILOG_INFO(1,"%{public}u",code);','}'))
    if case=='comma_status_known_gap':
        return '\n'.join(('int HILOG_INFO(int,const char*,...);',
            'unsigned Status(const char*value,int sel){',
            'switch(sel){case 0:return(HILOG_INFO(1,"%{public}s",value),0);default:return 0;}}',
            'void Callback(const char*key,int selector,bool flag){',
            'unsigned code=Status(key,selector);',
            'HILOG_INFO(1,"%{public}u",code);','}'))
    prefix=('#define UNKNOWN_CONTEXT 1' if case=='macro_context' else
            'bool GetFlag(const char*);' if case=='condition_escape' else
            'unsigned Consume(const char*);' if case=='return_escape' else '')
    result='unsigned' if case in ('literal_returns','return_escape') else 'void'
    before=('HILOG_INFO(1,"%{public}s",key);' if case=='real_pre_switch_log' else
            'if(flag){goto output;}' if case=='goto_live_label' else '')
    write=('output: ' if case=='goto_live_label' else '')+'*p=(unsigned char)key[0];'
    return '\n'.join((prefix,result+' Callback(const char*key,int selector,bool flag){',
        'unsigned out=0;unsigned*p=&out;',before,
        'switch(selector){'+CASES[case]+'}',write,
        'HILOG_INFO(1,"%{public}u",out);',
        'return 9;' if result!='void' else '', '}'))


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--worker');parser.add_argument('--case')
    parser.add_argument('--output',default='D:/openHarmonyScanner/outputs/D100_NESTED_RETURNS_20261020.json')
    args=parser.parse_args()
    if args.worker:
        support.source=source
        print(json.dumps(support.worker(args.worker,args.case),ensure_ascii=False));return
    result={'schema':1,'study':'D100 bounded if/else return arms; comma status observation is not a passing contract',
            'cases':{k:{'source':source(k),'sha256':hashlib.sha256(source(k).encode()).hexdigest(),
                        'known_gap':k=='comma_status_known_gap'} for k in CASES},'runs':[]}
    for revision in REVISIONS:
        raw=subprocess.check_output(['git','archive',revision,'src/'],cwd=support.support.REPO)
        snapshot=Path('D:/openHarmonyScanner/records/D100_nested_returns_20261020')/revision
        snapshot.mkdir(parents=True,exist_ok=True)
        with tarfile.open(fileobj=io.BytesIO(raw)) as tar:tar.extractall(snapshot,filter='data')
        runs={k:json.loads(subprocess.check_output([sys.executable,'-B',str(Path(__file__).resolve()),
              '--worker',str(snapshot),'--case',k],cwd=snapshot)) for k in CASES}
        result['runs'].append({'revision':revision,'src_archive_sha256':hashlib.sha256(raw).hexdigest(),'cases':runs})
        print(revision[:8],{k:[f['line'] for f in v['direct']['findings']] for k,v in runs.items()})
    output=Path(args.output);output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')


if __name__=='__main__':main()
