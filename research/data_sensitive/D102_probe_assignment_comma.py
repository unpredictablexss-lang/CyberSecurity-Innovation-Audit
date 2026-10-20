"""D102 original-byte syntax observations from archived src in fresh processes."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import D95_probe_loop_scope as support

REVISIONS=('9b77ae4341979c1fa49c502a74f14be4f87f4aa3','604d392e56d4deb922304caa2735133282e0cbb1')
MODULE='src/parser/cpp_assignment_comma.py'
CASES=('initializer','nested','call_argument','conditional','utf8_crlf','single_pointer_output',
       'illegal_double_comma','template_call','comment_in_paren','unmatched_span_gap','double_pointer_gap')


def source(case):
    if case in ('single_pointer_output','double_pointer_gap'):
        if case=='single_pointer_output':
            return ('void HILOG_INFO(int,const char*,...);unsigned Write(unsigned value,unsigned*out){return(*out=value,0);}\n'
                'void Callback(unsigned key){unsigned out=0;Write(key,&out);\nHILOG_INFO(1,"%{public}u",out);}')
        return ('void HILOG_INFO(int,const char*,...);unsigned Write(const char*value,const char**out){return(*out=value,0);}\n'
            'void Callback(const char*key){const char*out=nullptr;Write(key,&out);\nHILOG_INFO(1,"%{public}s",out);}')
    if case=='unmatched_span_gap':
        return ('int HILOG_INFO(int,const char*,...);unsigned Status(const char*value){const char*out=nullptr;'
                'return(out=value,HILOG_INFO(1,"%{public}s",out),0);}\nvoid Callback(const char*key){Status(key);}')
    expression={'nested':'((out=key,0),1)','call_argument':'Use((out=key,0))',
        'conditional':'(out=flag?key:"public",0)','illegal_double_comma':'(out=key,,0)',
        'template_call':'(out=Pick<0>(key),0)','comment_in_paren':'(out=key /* preserve */,0)'}.get(case,'(out=key,0)')
    prefix='template<int N>const char*Pick(const char*v){return v;}\n' if case=='template_call' else ''
    statement=expression+';' if case=='call_argument' else 'unsigned code='+expression+';'
    text=prefix+'void Use(unsigned);void HILOG_INFO(int,const char*,...);\nvoid Callback(const char*key,bool flag){const char*out=nullptr;'+statement+'\nHILOG_INFO(1,"%{public}s",out);}'
    return ('// 中文 before expression\n'+text).replace('\n','\r\n') if case=='utf8_crlf' else text


def worker(snapshot,case):
    support.SOURCE=source(case)
    result=support.worker(snapshot)
    from src.parser.ast import parse_source
    from src.ohscanner.frontend import index_sources
    from src.ohscanner.git_source import GitSource
    from src.ohscanner.detectors.data.sensitive_exposure import LocalFlow
    from src.ohscanner.detectors.data.models import SensitiveSourceModel
    import tree_sitter_cpp
    from tree_sitter import Language,Parser
    data=source(case).encode(); raw=Parser(Language(tree_sitter_cpp.language())).parse(data)
    index=parse_source(source(case),'cpp')
    units,_,_=index_sources((GitSource('service.cpp','cpp','0'*40,data),))
    flow=LocalFlow(units[0],SensitiveSourceModel('fixture/d95','d'*40,parameters=(('service.cpp','Callback',0),)))
    def walk(n):
        yield n
        for child in n.named_children:yield from walk(child)
    result['syntax']={'raw_cpp_error':raw.root_node.has_error,'shared':index.to_dict(),
        'private_root_error':flow.tree.root_node.has_error,
        'private_recoveries':getattr(flow.tree,'recovery_spans',()),'source_sha256':hashlib.sha256(data).hexdigest(),
        'private_root_bytes':flow.tree.root_node.end_byte,
        'assignment_comma_nodes':[{'type':n.type,'start':n.start_byte,'end':n.end_byte,
            'raw_span':data[n.start_byte:n.end_byte].decode(),'parent_type':n.parent.type if n.parent else None}
            for n in walk(flow.tree.root_node) if n.type in ('assignment_expression','comma_expression')]}
    return result


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--worker');parser.add_argument('--case')
    parser.add_argument('--output',default='D:/openHarmonyScanner/outputs/D102_ASSIGNMENT_COMMA_20261020.json')
    args=parser.parse_args()
    if args.worker:
        print(json.dumps(worker(args.worker,args.case),ensure_ascii=False));return
    result={'schema':1,'study':'D102 same-span common expression recovery; unknowns are not safety passes',
        'cases':{k:{'source':source(k),'source_sha256':hashlib.sha256(source(k).encode()).hexdigest(),
            'known_gap_not_passed':k.endswith('_gap')} for k in CASES},'runs':[]}
    for revision in REVISIONS:
        archive=subprocess.check_output(['git','archive',revision,'src/'],cwd=support.REPO)
        snapshot=Path('D:/openHarmonyScanner/records/D102_assignment_comma_20261020')/revision
        snapshot.mkdir(parents=True,exist_ok=True)
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:tar.extractall(snapshot,filter='data')
        cases={k:json.loads(subprocess.check_output([sys.executable,'-B',str(Path(__file__).resolve()),
            '--worker',str(snapshot),'--case',k],cwd=snapshot)) for k in CASES}
        module=subprocess.run(['git','show',revision+':'+MODULE],cwd=support.REPO,capture_output=True)
        result['runs'].append({'revision':revision,'src_archive_sha256':hashlib.sha256(archive).hexdigest(),
            'module_sha256':hashlib.sha256(module.stdout).hexdigest() if module.returncode==0 else None,'cases':cases})
        print(revision[:8],{k:(r['syntax']['shared']['parse_status'],len(r['direct']['findings']),len(r['runner']['diagnostics'])) for k,r in cases.items()})
    Path(args.output).write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')


if __name__=='__main__':main()
