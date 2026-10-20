"""D101 frozen value/effects controls, type-proof observations and parser gap."""
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

REVISIONS=('04d06da236ed46c277fe3b756a3a42c95ce7ab98',
           'ecaa9b0c32df2fb1688027a1b0e2af67c79bf540')
PROOF='src/ohscanner/detectors/data/comma_values.py'
CASES=('scalar_zero','multi_zero','nested_zero','status_sink','final_material',
       'final_conditional','unique_call','unknown_final','overloaded_operator',
       'class_sink','callable_shadow','macro_context','partial_header','alias_scope',
       'overloaded_declaration','noncomma','assignment_effect','parser_gap')


def source(case):
    if case=='status_sink':
        return '\n'.join(('int HILOG_INFO(int,const char*,...);',
            'unsigned Status(const char*value,int sel){',
            'switch(sel){case 0:return(HILOG_INFO(1,"%{public}s",value),0);default:return 0;}}',
            'void Callback(const char*key,int selector){',
            'unsigned code=Status(key,selector);',
            'HILOG_INFO(1,"%{public}u",code);','}'))
    if case in ('overloaded_operator','class_sink','callable_shadow'):
        if case=='class_sink':
            return ('struct Box{const char*text;};Box HILOG_INFO(int,const char*,...);'
                'const char*operator,(Box box,int){return box.text;}'
                'const char*Select(const char*value){return(HILOG_INFO(1,"%{public}s",value),0);}'
                'void Callback(const char*key){const char*out=Select(key);HILOG_INFO(1,"%{public}s",out);}')
        if case=='callable_shadow':
            return ('void HILOG_INFO(int,const char*,...);struct Box{const char*text;};int Audit(const char*);'
                'const char*operator,(Box box,int){return box.text;}'
                'void Callback(const char*key,Box(*Audit)(const char*)){'
                'const char*out=(Audit(key),0);HILOG_INFO(1,"%{public}s",out);}')
        return ('void HILOG_INFO(int,const char*,...);struct Box{const char*text;};'
                'Box Wrap(const char*value){return{value};}'
                'const char*operator,(Box box,int){return box.text;}'
                'const char*Select(const char*value){return(Wrap(value),0);}'
                'void Callback(const char*key){const char*out=Select(key);HILOG_INFO(1,"%{public}s",out);}')
    if case in ('assignment_effect','parser_gap'):
        expression='((out=key),0)' if case=='assignment_effect' else '(out=key,0)'
        return '\n'.join(('void HILOG_INFO(int,const char*,...);',
            'void Callback(const char*key){const char*out=nullptr;',
            'unsigned code='+expression+';','HILOG_INFO(1,"%{public}s",out);','}'))
    prefix=('#define BUILD_FLAG 1' if case=='macro_context' else
            'using Number=unsigned;' if case=='alias_scope' else
            'int Audit(const char*);int Audit(int);' if case=='overloaded_declaration' else
            'int Audit(const char*);' if case=='unique_call' else
            'const char*Unknown(const char*);' if case=='unknown_final' else '')
    expressions={'scalar_zero':'(key,0)','multi_zero':'(key,7,0)',
        'nested_zero':'((key,0),1)','unique_call':'(Audit(key),0)',
        'overloaded_declaration':'(Audit(key),0)', 'final_material':'(0,7,key)',
        'final_conditional':'(0,flag?key:"public")','unknown_final':'(0,Unknown(key))',
        'noncomma':'(key)'}
    expression=expressions.get(case,'(key,0)')
    pointer=case in ('final_material','final_conditional','unknown_final','noncomma')
    variable=('const char*out=' if pointer else 'unsigned code=')+expression+';'
    log='HILOG_INFO(1,"%{public}s",out);' if pointer else 'HILOG_INFO(1,"%{public}u",code);'
    return '\n'.join((prefix,'void HILOG_INFO(int,const char*,...);',
        'void Callback(const char*key,bool flag){',variable,log,'}'))


def worker(snapshot,case):
    sys.path.insert(0,snapshot);observations=[]
    try:
        from src.ohscanner.detectors.data.comma_values import BuiltinCommaProof
    except ModuleNotFoundError:
        BuiltinCommaProof=None
    if BuiltinCommaProof is not None:
        original=BuiltinCommaProof.is_builtin
        def observed(proof,node):
            result=original(proof,node)
            left=node.child_by_field_name('left');right=node.child_by_field_name('right')
            observations.append({'file':proof.flow.u.path,'line':node.start_point[0]+1,
                'start_byte':node.start_byte,'end_byte':node.end_byte,
                'left_ast':left.type,'right_ast':right.type,
                'left_text':proof.flow.text(left),'right_text':proof.flow.text(right),
                'proof_environment_enabled':proof.enabled,'is_builtin':result,
                'left_pointer_depth':proof.kind(left) if proof.enabled else None,
                'right_pointer_depth':proof.kind(right) if proof.enabled else None})
            return result
        BuiltinCommaProof.is_builtin=observed
    support.source=source;result=support.worker(snapshot,case)
    result['builtin_type_proof']=list({json.dumps(row,sort_keys=True):row for row in observations}.values())
    result['builtin_type_proof_available']=BuiltinCommaProof is not None
    return result


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--worker');parser.add_argument('--case')
    parser.add_argument('--output',default='D:/openHarmonyScanner/outputs/D101_COMMA_VALUES_20261020.json')
    args=parser.parse_args()
    if args.worker:
        print(json.dumps(worker(args.worker,args.case),ensure_ascii=False));return
    result={'schema':1,'study':'D101 builtin comma result role distinct from operand effects',
            'cases':{k:{'source':source(k),'sha256':hashlib.sha256(source(k).encode()).hexdigest(),
                        'parser_gap_not_passed':k=='parser_gap'} for k in CASES},'runs':[]}
    for revision in REVISIONS:
        raw=subprocess.check_output(['git','archive',revision,'src/'],cwd=support.support.REPO)
        snapshot=Path('D:/openHarmonyScanner/records/D101_comma_values_20261020')/revision
        snapshot.mkdir(parents=True,exist_ok=True)
        with tarfile.open(fileobj=io.BytesIO(raw)) as tar:tar.extractall(snapshot,filter='data')
        runs={k:json.loads(subprocess.check_output([sys.executable,'-B',str(Path(__file__).resolve()),
              '--worker',str(snapshot),'--case',k],cwd=snapshot)) for k in CASES}
        module=subprocess.run(['git','show',revision+':'+PROOF],cwd=support.support.REPO,capture_output=True)
        result['runs'].append({'revision':revision,'src_archive_sha256':hashlib.sha256(raw).hexdigest(),
            'proof_module_sha256':hashlib.sha256(module.stdout).hexdigest() if module.returncode==0 else None,'cases':runs})
        print(revision[:8],{k:([f['line'] for f in v['direct']['findings']],
            [f['line'] for f in v['runner']['diagnostics']]) for k,v in runs.items()})
    output=Path(args.output);output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')


if __name__=='__main__':main()
