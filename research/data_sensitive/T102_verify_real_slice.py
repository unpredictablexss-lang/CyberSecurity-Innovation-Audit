"""Independently pin and replay the D103 arkui_napi helper slice; no target execution."""
from __future__ import annotations
import argparse,hashlib,io,json,os,re,subprocess,sys,tarfile,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
REV='bfe8fad581ca6112e7d55c38ca60150753f4af35'
REPOSITORY='openharmony/arkui_napi'
BEFORE='9b77ae4341979c1fa49c502a74f14be4f87f4aa3'
AFTER='b339ff312329b0246bd8170a995e2872b00a3fe1'
SELECTED=('tools/check_helper.cpp','tools/check_helper.h','tools/api_meta.h')
METADATA=('tools/BUILD.gn','BUILD.gn','napi.gni','bundle.json')


def git(directory,*args):
    env=os.environ.copy();env.update(GIT_NO_LAZY_FETCH='1',GIT_ALLOW_PROTOCOL='',GIT_TERMINAL_PROMPT='0')
    return subprocess.check_output(['git','-c','remote.origin.promisor=false','--git-dir',str(directory),*args],env=env,stderr=subprocess.PIPE,timeout=30)


def blob(directory,path):return git(directory,'cat-file','blob',REV+':'+path)


def describe(directory,path):
    data=blob(directory,path);oid=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
    actual=git(directory,'rev-parse',REV+':'+path).decode().strip()
    if actual!=oid:raise ValueError('blob OID mismatch: '+path)
    data.decode('utf-8')
    return {'path':path,'blob':oid,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'utf8_strict':True}


def source_manifest(directory):
    tree=git(directory,'rev-parse',REV+'^{tree}').decode().strip()
    all_paths=git(directory,'ls-tree','-r','--name-only',REV).decode().splitlines()
    rows=[describe(directory,p) for p in SELECTED]
    docs=[describe(directory,p) for p in METADATA]
    build=blob(directory,'tools/BUILD.gn').decode()
    target=re.search(r'ohos_executable\("checkapi"\)\s*\{',build)
    assignment=re.search(r'\bsources\s*=\s*\[([^]]+)\]',build[target.end():],re.S)
    names=re.findall(r'"([^"\n]+\.cpp)"',assignment.group(1))
    target_sources=['tools/'+name for name in names]
    if not names or 'tools/check_helper.cpp' not in target_sources:raise ValueError('BUILD source membership absent')
    start=target.end()+assignment.start();end=target.end()+assignment.end()
    include_rows=[]
    for row in rows:
        data=blob(directory,row['path']);text=data.decode()
        for match in re.finditer(r'^\s*#include\s*([<"])([^>"\n]+)[>"]',text,re.M):
            name=match.group(2);candidates=[p for p in all_paths if p==name or p.endswith('/'+name)]
            local=str(Path(row['path']).parent/Path(name)).replace('\\','/')
            if local in all_paths:candidates=sorted(set([local,*candidates]))
            include_rows.append({'from':row['path'],'line':text[:match.start()].count('\n')+1,'include':name,
                'syntax':'quoted' if match.group(1)=='"' else 'system','same_tree_path_candidates':candidates,
                'selected_candidates':[p for p in candidates if p in SELECTED],
                'resolution':'path candidates only; compiler include order, conditions and external versions not evaluated'})
    try:
        origin=git(directory,'config','--get','remote.origin.url').decode().strip()
        origin_state={'status':'configured_value','value':origin,'interpretation':'Local configuration only, not upstream authentication.'}
    except subprocess.CalledProcessError as error:
        origin_state={'status':'unknown','command_exit':error.returncode,'reason':'No configured remote.origin.url value; object identity is verified independently.'}
    return {'schema':1,'repository':REPOSITORY,'commit':REV,'tree':tree,'source_files':rows,'build_metadata':docs,
        'source_bytes':sum(r['bytes'] for r in rows),'build_boundary':{'target':'//foundation/arkui/napi/tools:checkapi',
            'build_file':'tools/BUILD.gn','target_line':build[:target.start()].count('\n')+1,
            'sources_assignment_line':build[:start].count('\n')+1,'sources_assignment':build[start:end],
            'sources_assignment_sha256':hashlib.sha256(build[start:end].encode()).hexdigest(),
            'literal_target_sources':target_sources,'selected_target_sources':[p for p in target_sources if p in SELECTED],
            'unselected_target_sources':[p for p in target_sources if p not in SELECTED],
            'headers':'selected only as local header closure; no claim that GN sources enumerates all headers',
            'configuration':'not_run: GN generation/compiler/linking/target execution not performed; build variables and dependency graph unknown'},
        'includes':include_rows,'configured_origin':origin_state,
        'selection':'Bounded helper plus two local headers, not complete checkapi/ace_napi/Ark/STL analysis.',
        'retrieval':'Local pinned Git objects only; lazy fetch disabled; no target execution.',
        'search_notes':'Initial HEAD probes on commonlibrary_c_utils/commonlibrary_utils_lite/bounds stores had no HEAD ref; explicit arkui_napi fixed objects are readable. Missing HEAD/config was not treated as scan safety.'}


def walk(node):
    yield node
    for child in node.named_children:yield from walk(child)


def child(args):
    sys.path.insert(0,str(args.snapshot_root));sys.path.insert(1,str(ROOT))
    from dataclasses import asdict
    from src.ohscanner.contracts import ScanContext,ScanRequest
    from src.ohscanner.frontend import index_sources
    from src.ohscanner.git_source import GitSource
    from src.ohscanner.fixture import snapshot_digest
    from src.ohscanner.runner import DetectorRegistry,run_all_with_coverage
    from src.ohscanner.detectors.data.sensitive_exposure import SensitiveExposureDetector,LocalFlow,CrossFileResolver
    from src.ohscanner.detectors.data.models import SensitiveSourceModel,SINKS
    manifest=json.loads(args.manifest.read_text(encoding='utf-8'));actual=source_manifest(args.git_dir)
    for key in ('commit','tree','source_files','build_metadata','source_bytes','build_boundary','includes'):
        if actual[key]!=manifest[key]:raise ValueError('Pinned manifest changed: '+key)
    sources=[GitSource(r['path'],'cpp',r['blob'],blob(args.git_dir,r['path'])) for r in manifest['source_files']]
    units,ast,_=index_sources(tuple(sources));units=tuple(sorted(units,key=lambda u:u.path))
    request=ScanRequest('t102-independent-real-helper',REPOSITORY,REV,snapshot_digest(units),
        'current-component:'+REPOSITORY,profile_id='light-ast',provenance='git_object')
    context=ScanContext(request,units,{'ast':ast});detector=SensitiveExposureDetector()
    direct=detector.detect(context,units);registry=DetectorRegistry();registry.register(detector)
    reports,coverage=run_all_with_coverage(context,registry)
    profile_found=any((m.repository,m.commit)==(REPOSITORY,REV) for m in detector.models)
    heuristic_model=SensitiveSourceModel('unreviewed/heuristic','0'*40,fields=(),non_sensitive_fields=(),output_calls=(),parameters=(),provenance='Unreviewed sensitive-name heuristic only')
    resolver=CrossFileResolver(units,heuristic_model,True)
    resolver.switch_join_scope_complete=all(u.parse_status=='complete' and ast[u.path]['parse_status']=='complete'
        and not re.search(r'^\s*#',u.text,re.M) for u in units)
    features={};calls={};raw_checks=[]
    sink_names={s.name for s in SINKS}
    for unit in units:
        raw=blob(args.git_dir,unit.path);indexed=unit.text.encode()
        if raw!=indexed or hashlib.sha256(raw).hexdigest()!=unit.sha256:raise ValueError('raw/index byte drift')
        flow=LocalFlow(unit,heuristic_model,True,resolver);switches=[];if_returns=[]
        def direct_return(node):
            if node is None:return False
            if node.type=='else_clause' and len(node.named_children)==1:return direct_return(node.named_children[0])
            if node.type=='compound_statement':
                statements=[c for c in node.named_children if c.type!='comment']
                return len(statements)==1 and direct_return(statements[0])
            return node.type=='return_statement'
        for node in walk(flow.tree.root_node):
            if node.type=='if_statement' and direct_return(node.child_by_field_name('consequence')) and direct_return(node.child_by_field_name('alternative')):
                if_returns.append({'line':node.start_point[0]+1,'start_byte':node.start_byte,'end_byte':node.end_byte})
            if node.type!='switch_statement':continue
            body=node.child_by_field_name('body');arms=[]
            for case in body.named_children if body else []:
                if case.type!='case_statement':continue
                label=case.child_by_field_name('value')
                statements=[c for c in case.named_children if c.type!='comment' and (label is None or c.id!=label.id)]
                arms.append({'label':flow.text(label) if label else 'default','label_type':label.type if label else None,
                    'line':case.start_point[0]+1,'statement_types':[c.type for c in statements],
                    'direct_return':len(statements)==1 and direct_return(statements[0])})
            switches.append({'line':node.start_point[0]+1,'start_byte':node.start_byte,'end_byte':node.end_byte,
                'source_span_sha256':hashlib.sha256(raw[node.start_byte:node.end_byte]).hexdigest(),'arms':arms,
                'bounded_dispatch_admitted':flow.exact_switch_cases(node) is not None})
        rows=[]
        for call in ast[unit.path]['calls']:
            start,end=call['start_byte'],call['end_byte']
            if not (0<=start<end<=len(raw)) or raw[:start].count(b'\n')+1!=call['line']:raise ValueError('call offset drift')
            rows.append({**call,'original_span_sha256':hashlib.sha256(raw[start:end]).hexdigest()})
        calls[unit.path]=rows
        stream_outputs=[]
        for node in walk(flow.tree.root_node):
            if node.type!='binary_expression' or flow.text(node.child_by_field_name('operator'))!='<<':continue
            parent=node.parent
            if parent is not None and parent.type=='binary_expression' and flow.text(parent.child_by_field_name('operator'))=='<<':continue
            text=flow.text(node)
            if text.startswith('g_logFile') or text.startswith('std::cerr'):
                stream_outputs.append({'line':node.start_point[0]+1,'start_byte':node.start_byte,'end_byte':node.end_byte,
                    'source_span_sha256':hashlib.sha256(raw[node.start_byte:node.end_byte]).hexdigest(),
                    'expression':text,'material_binding':'unknown; actual output syntax, not a proved sensitive flow'})
        features[unit.path]={'stream_output_syntax':stream_outputs,'frontend':unit.parse_status,'private_root_has_error':flow.tree.root_node.has_error,
            'private_end_byte':flow.tree.root_node.end_byte,'switches':switches,'single_if_else_direct_return':if_returns,
            'comma_expression_count':sum(n.type=='comma_expression' for n in walk(flow.tree.root_node)),
            'assignment_comma_recovery_spans':list(getattr(flow.tree,'recovery_spans',())),
            'builtin_comma_type_scope_enabled':flow.comma_values.enabled,
            'recognized_sink_call_sites':[c for c in rows if c['name'] in sink_names],
            'all_return_statement_count':sum(n.type=='return_statement' for n in walk(flow.tree.root_node))}
        raw_checks.append({'file':unit.path,'raw_sha256':hashlib.sha256(raw).hexdigest(),'indexed_sha256':hashlib.sha256(indexed).hexdigest(),'raw_equals_indexed':True})
    result={'schema':1,'scanner_revision':args.revision,'version':detector.version,'repository':REPOSITORY,'commit':REV,
        'tree':manifest['tree'],'manifest_sha256':hashlib.sha256(args.manifest.read_bytes()).hexdigest(),
        'snapshot_sha256':request.snapshot_sha256,'raw_checks':raw_checks,'features':features,'call_facts':calls,
        'source_profile':{'reviewed_profile_found':profile_found,'mode':'reviewed' if profile_found else 'unreviewed sensitive-name heuristic',
            'interpretation':'No sensitive truth labels or product binding established'},
        'precision_gate':{'whole_selected_scope_complete_and_preprocessing_free':resolver.switch_join_scope_complete,
            'single_unit':len(units)==1},'direct':asdict(direct),'runner':reports[0].to_dict(),'coverage':coverage,
        'target_execution':'not_run','build_execution':'not_run','network_access':'not attempted',
        'interpretation':'Zero candidates, if observed, is not safety: report profile and detector coverage separately.'}
    args.output.write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')


def changes(a,b,path=''):
    if isinstance(a,dict) and isinstance(b,dict):
        return [p for k in sorted(a.keys()|b.keys()) for p in (changes(a[k],b[k],path+'/'+k) if k in a and k in b else [path+'/'+k])]
    if isinstance(a,list) and isinstance(b,list) and len(a)==len(b):
        return [p for i,(x,y) in enumerate(zip(a,b)) for p in changes(x,y,path+'/'+str(i))]
    return [path] if a!=b else []


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--git-dir',type=Path,required=True);parser.add_argument('--manifest',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True);parser.add_argument('--cache',type=Path)
    parser.add_argument('--snapshot-root',type=Path);parser.add_argument('--revision')
    args=parser.parse_args()
    if args.snapshot_root:
        try:child(args)
        except Exception as error:
            args.output.write_text(json.dumps({'status':'not_run','error_type':type(error).__name__,'error':str(error)},indent=2)+'\n',encoding='utf-8');raise
        return
    if not args.cache:parser.error('--cache required')
    if not args.manifest.exists():args.manifest.write_text(json.dumps(source_manifest(args.git_dir),indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    args.cache.mkdir(parents=True,exist_ok=True);runs=[]
    for revision in (BEFORE,AFTER):
        archive=subprocess.check_output(['git','-C',str(ROOT),'archive',revision,'src/'])
        destination=Path(tempfile.mkdtemp(prefix='t102_'+revision[:10]+'_',dir=args.cache.resolve()))
        with tarfile.open(fileobj=io.BytesIO(archive)) as bundle:bundle.extractall(destination,filter='data')
        output=destination/'result.json'
        command=[sys.executable,str(Path(__file__).resolve()),'--snapshot-root',str(destination),'--revision',revision,
            '--git-dir',str(args.git_dir),'--manifest',str(args.manifest.resolve()),'--output',str(output)]
        process=subprocess.run(command,timeout=120)
        row=json.loads(output.read_text(encoding='utf-8'))
        row.update(src_archive_sha256=hashlib.sha256(archive).hexdigest(),src_tree_oid=subprocess.check_output(['git','-C',str(ROOT),'rev-parse',revision+':src']).decode().strip())
        runs.append(row)
        if process.returncode:args.output.write_text(json.dumps({'runs':runs,'status':'not_run'},indent=2,ensure_ascii=False)+'\n',encoding='utf-8');raise SystemExit(2)
    a,b=runs;coverage_changes=changes(a['coverage'],b['coverage'])
    result={'schema':1,'study':'T102 independent pinned real C++ source slice','manifest_sha256':hashlib.sha256(args.manifest.read_bytes()).hexdigest(),'runs':runs,
        'comparison':{'direct_findings_equal':a['direct']['findings']==b['direct']['findings'],
            'runner_diagnostics_equal':a['runner']['diagnostics']==b['runner']['diagnostics'],
            'features_equal':a['features']==b['features'],'call_facts_equal':a['call_facts']==b['call_facts'],
            'coverage_equal':a['coverage']==b['coverage'],'coverage_changed_paths':coverage_changes,
            'coverage_changed_only_binding_version':bool(coverage_changes) and all(p.endswith('/source_binding/detector_version') for p in coverage_changes)},
        'interpretation':'Fixed bounded source-level replay, not full target/build/product verification; absent feature or zero candidates is not safety.'}
    args.output.write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    print(json.dumps({'versions':[r['version'] for r in runs],'source_bytes':33437,
        'direct':[len(r['direct']['findings']) for r in runs],'runner':[len(r['runner']['diagnostics']) for r in runs],
        'status':[r['runner']['status'] for r in runs],'calls':[sum(len(c) for c in r['call_facts'].values()) for r in runs],
        'comparison':result['comparison']}))

if __name__=='__main__':main()
