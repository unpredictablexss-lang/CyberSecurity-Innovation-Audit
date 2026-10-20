"""D103 read-only fixed OpenHarmony checkapi source/BUILD replay. No target execution."""
import argparse
from dataclasses import asdict
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import tarfile

REPO=Path(__file__).resolve().parents[2]
STORE='D:/openHarmonyScanner/openharmony/.repo/project-objects/arkui_napi.git'
ORIGIN='openharmony/arkui_napi'
COMMIT='bfe8fad581ca6112e7d55c38ca60150753f4af35'
SCANNER='b339ff312329b0246bd8170a995e2872b00a3fe1'
SOURCES=('tools/check_helper.cpp','tools/check_helper.h','tools/api_meta.h')
BUILD=('tools/BUILD.gn','BUILD.gn','napi.gni','bundle.json')


def git(*args):return subprocess.check_output(['git','--git-dir',STORE,*args])

def rawfile(path):
    oid=git('rev-parse',COMMIT+':'+path).decode().strip()
    raw=git('cat-file','blob',oid)
    actual=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
    if actual!=oid:raise ValueError('object mismatch: '+path)
    return oid,raw


def manifest():
    result={'repository':ORIGIN,'commit':COMMIT,'tree':git('rev-parse',COMMIT+'^{tree}').decode().strip(),
        'git_store':STORE,'selected_source_paths':list(SOURCES),'source_files':[],'build_context':[],
        'target':'//foundation/arkui/napi/tools:checkapi','build_executed':'not_run',
        'scope_boundary':'Three exact source/header objects; not all six target cpp sources, not transitive dependency closure. Full same-revision BUILD metadata retained; host/platform flags and external repository versions unbound.'}
    tree_paths=git('ls-tree','-r','--name-only',COMMIT).decode().splitlines()
    origin=subprocess.run(['git','--git-dir',STORE,'config','--get','remote.origin.url'],capture_output=True,text=True)
    result['configured_origin_url']=origin.stdout.strip() or 'unknown'
    for path in SOURCES+BUILD:
        oid,raw=rawfile(path)
        entry={'path':path,'blob':oid,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
        if path in BUILD:entry['full_text']=raw.decode()
        else:entry['includes']=[{'delimiter':m[0],'path':m[1]} for m in re.findall(r'^\s*#\s*include\s*([<"])([^>"\n]+)[>"]',raw.decode(),re.M)]
        if path in SOURCES:
            for include in entry['includes']:
                name=include['path']
                choices=[p for p in tree_paths if p==name or p.endswith('/'+name)]
                include['same_repo_path_candidates']=choices
                include['binding']='selected direct local include' if any(c in SOURCES for c in choices) else ('same-repo available, not expanded or compiler-bound' if choices else 'outside this tree or compiler/system path; binding unknown')
        result['source_files' if path in SOURCES else 'build_context'].append(entry)
    target_source=('check_api.cpp','check_helper.cpp','check_match.cpp','load_abc.cpp','load_so.cpp','parse_json.cpp')
    result['declared_target_sources']=['tools/'+p for p in target_source]
    result['target_sources_not_scanned']=[p for p in result['declared_target_sources'] if p not in SOURCES]
    return result


def worker(snapshot):
    sys.path.insert(0,snapshot)
    from src.ohscanner.contracts import ScanContext,ScanRequest
    from src.ohscanner.detectors.data.sensitive_exposure import SensitiveExposureDetector,LocalFlow
    from src.ohscanner.fixture import snapshot_digest
    from src.ohscanner.frontend import index_sources
    from src.ohscanner.git_source import GitSource
    from src.ohscanner.runner import DetectorRegistry,run_all_with_coverage
    from src.parser.ast import parse_source
    sources=[]
    for path in SOURCES:
        oid,raw=rawfile(path);sources.append(GitSource(path,'cpp',oid,raw))
    units,ast,_=index_sources(tuple(sorted(sources,key=lambda item:item.path)))
    request=ScanRequest('d103-checkapi',ORIGIN,COMMIT,snapshot_digest(units),
        'current-component:'+ORIGIN,profile_id='light-ast',provenance='git_object')
    ctx=ScanContext(request,units,{'ast':ast})
    class ObservedDetector(SensitiveExposureDetector):
        def __init__(self):
            super().__init__();self.observed=[]
        def make_flow(self,*args,**kwargs):
            flow=super().make_flow(*args,**kwargs);self.observed.append(flow);return flow
    detector=ObservedDetector()
    direct=detector.detect(ctx,units)
    direct_sites=[{'file':flow.u.path,'source_sites':flow.source_sites,'sink_sites':flow.sink_sites} for flow in detector.observed]
    registry=DetectorRegistry();registry.register(detector)
    reports,coverage=run_all_with_coverage(ctx,registry)
    def walk(node):
        yield node
        for child in node.named_children:yield from walk(child)
    shapes={};calls=[]
    for unit in units:
        flow=LocalFlow(unit,detector.model);rows=[];comma=[]
        for node in walk(flow.tree.root_node):
            if node.type=='switch_statement':
                body=node.child_by_field_name('body');cases=[n for n in body.named_children if n.type=='case_statement'] if body else []
                labels=[]
                for case in cases:
                    label=case.child_by_field_name('value')
                    labels.append({'text':flow.text(label) if label else 'default','ast':label.type if label else None})
                rows.append({'start_line':node.start_point[0]+1,'end_line':node.end_point[0]+1,'start_byte':node.start_byte,'end_byte':node.end_byte,'raw_span_sha256':hashlib.sha256(flow.b[node.start_byte:node.end_byte]).hexdigest(),'labels':labels,'bounded_dispatch_admitted':flow.exact_switch_cases(node) is not None,'return_statements':sum(n.type=='return_statement' for n in walk(node))})
            if node.type=='comma_expression':
                comma.append({'line':node.start_point[0]+1,'start_byte':node.start_byte,'end_byte':node.end_byte,'text':flow.text(node),'has_assignment':any(n.type=='assignment_expression' for n in walk(node))})
        shared_index=parse_source(unit.text,'cpp')
        shapes[unit.path]={'parse_status':unit.parse_status,'parse_issues':unit.parse_issues,
            'private_root_error':flow.tree.root_node.has_error,'switches':rows,'comma_expressions':comma,
            'recovery_spans':getattr(flow.tree,'recovery_spans',()),'preprocessor_present':bool(re.search(r'^\s*#',unit.text,re.M)),
            'functions':ast[unit.path]['functions'],'returns_total':sum(n.type=='return_statement' for n in walk(flow.tree.root_node))}
        for call in ast[unit.path]['calls']:
            calls.append({'file':unit.path,**call,'raw_span_sha256':hashlib.sha256(flow.b[call['start_byte']:call['end_byte']]).hexdigest()})
    t85=[]
    prior=json.loads((REPO/'research/data_sensitive/T85_SOURCE_MANIFEST.json').read_text(encoding='utf-8'))
    cert=next(c for c in prior['components'] if c['key']=='cert')
    cert_store='D:/openHarmonyScanner/openharmony/.repo/project-objects/security_certificate_framework.git'
    for item in cert['files']:
        blob=subprocess.check_output(['git','--git-dir',cert_store,'rev-parse',cert['commit']+':'+item['path']]).decode().strip()
        raw=subprocess.check_output(['git','--git-dir',cert_store,'cat-file','blob',blob])
        if blob!=item['blob'] or hashlib.sha256(raw).hexdigest()!=item['sha256']:raise ValueError('T85 object mismatch')
        indexed,_,_=index_sources((GitSource(item['path'],'cpp',blob,raw),))
        parsed=LocalFlow(indexed[0],detector.model);all_nodes=list(walk(parsed.tree.root_node))
        t85.append({**item,'parse_status':indexed[0].parse_status,'switch_count':sum(n.type=='switch_statement' for n in all_nodes),'comma_count':sum(n.type=='comma_expression' for n in all_nodes),'recovery_spans':getattr(parsed.tree,'recovery_spans',())})
    return {'version':detector.version,'request':asdict(request),'direct':asdict(direct),
        'runner':asdict(reports[0]),'coverage':coverage,'shapes':shapes,'calls':calls,'actual_direct_sites':direct_sites,'t85_shape_reference':{'repository':cert['repository'],'commit':cert['commit'],'files':t85,'interpretation':'AST inventory only here; full24/638 pipeline compatibility is pinned in D102/T101.'}}


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--worker');parser.add_argument('--scanner',default=SCANNER)
    parser.add_argument('--output',default='D:/openHarmonyScanner/outputs/D103_REAL_CPP_REPLAY_20261020.json')
    args=parser.parse_args()
    if args.worker:print(json.dumps(worker(args.worker),ensure_ascii=False));return
    revision=subprocess.check_output(['git','rev-parse',args.scanner],cwd=REPO).decode().strip()
    archive=subprocess.check_output(['git','archive',revision,'src/'],cwd=REPO)
    snapshot=Path('D:/openHarmonyScanner/records/D103_real_cpp_20261020')/revision
    snapshot.mkdir(parents=True,exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:tar.extractall(snapshot,filter='data')
    result={'schema':1,'study':'D103 real C++ checkapi slice, source-level only','scanner_revision':revision,
        'src_tree':subprocess.check_output(['git','rev-parse',revision+':src'],cwd=REPO).decode().strip(),
        'src_archive_sha256':hashlib.sha256(archive).hexdigest(),'manifest':manifest(),
        'scan':json.loads(subprocess.check_output([sys.executable,'-B',str(Path(__file__).resolve()),'--worker',str(snapshot)],cwd=snapshot))}
    Path(args.output).write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(result['manifest']['tree'],'version',result['scan']['version'],'direct',len(result['scan']['direct']['findings']),'Runner',len(result['scan']['runner']['diagnostics']))
    print({k:(v['parse_status'],len(v['switches']),len(v['comma_expressions'])) for k,v in result['scan']['shapes'].items()})


if __name__=='__main__':main()
