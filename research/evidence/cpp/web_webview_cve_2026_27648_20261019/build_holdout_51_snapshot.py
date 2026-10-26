import hashlib, json, os, subprocess
from pathlib import Path
from src.parser.ast import parse_source
source_repo=r'D:\openHarmonyScanner\tmp\chromium-src-cve-2026-27648-audit.git'
outdir=Path(r'D:\openHarmonyScanner\tmp\web-webview-flowbuf-holdout-51-m2-20261019')
evidence=Path('research/evidence/cpp/web_webview_cve_2026_27648_20261019/holdout-51-source-identities.json')
env=os.environ.copy(); env['GIT_NO_LAZY_FETCH']='1'
if outdir.exists() and any(outdir.iterdir()): raise SystemExit(f'refusing non-empty directory: {outdir}')
outdir.mkdir(parents=True,exist_ok=True)
subprocess.run(['git','init','-q',str(outdir)],check=True)
subprocess.run(['git','-C',str(outdir),'config','user.name','OHScanner Evidence'],check=True)
subprocess.run(['git','-C',str(outdir),'config','user.email','evidence@example.invalid'],check=True)
items={'vulnerable':('5e47fecda669ff1f8834e11ab9cc9aaa2502355b','ohos_nweb/src/cef_delegate/nweb_handler_delegate.cc'),'fixed':('9082c13cea0f423b99ba0dc7ca105515e7373d44','ohos_nweb/src/cef_delegate/nweb_handler_delegate.cc')}
manifest={'designation':'independent same-mechanism held-out release branch; not used to author/refine detector v0.3.6','source_repository':'OpenHarmony-TPC/chromium_src','source_files':{},'snapshots':{}}
for label,(commit,path) in items.items():
 raw=subprocess.check_output(['git','-C',source_repo,'show',f'{commit}:{path}'],env=env,timeout=20).decode('utf-8')
 parsed=parse_source(raw,'cpp')
 targets=[f for f in parsed.functions if f.name in {'FlowbufStrAtIndex','ProcessNativeProxyResultNewFlowbuf'}]
 if len(targets)!=2: raise SystemExit(f'{label} expected 2 target functions, got {len(targets)}')
 fragment='\n\n'.join('\n'.join(raw.splitlines()[f.start_line-1:f.end_line]) for f in sorted(targets,key=lambda f:f.start_line))+'\n'
 fp=parse_source(fragment,'cpp')
 if fp.parse_status!='complete': raise SystemExit(f'{label} fragment parse {fp.parse_status}: {fp.parse_issues}')
 (outdir/'flowbuf_functions.cc').write_text(fragment,encoding='utf-8',newline='\n')
 subprocess.run(['git','-C',str(outdir),'add','flowbuf_functions.cc'],check=True)
 subprocess.run(['git','-C',str(outdir),'commit','-qm',label],check=True)
 synthetic=subprocess.check_output(['git','-C',str(outdir),'rev-parse','HEAD']).decode().strip()
 tree=subprocess.check_output(['git','-C',str(outdir),'rev-parse','HEAD^{tree}']).decode().strip()
 manifest['source_files'][label]={'upstream_commit':commit,'path':path,'blob':subprocess.check_output(['git','-C',source_repo,'rev-parse',f'{commit}:{path}'],env=env).decode().strip(),'bytes':len(raw.encode()),'sha256':hashlib.sha256(raw.encode()).hexdigest(),'fragment_sha256':hashlib.sha256(fragment.encode()).hexdigest(),'fragment_bytes':len(fragment.encode()),'parse_status_full_file':parsed.parse_status,'parse_status_fragment':fp.parse_status,'parse_issues_full_file':len(parsed.parse_issues),'function_ranges':[{'name':f.name,'start_line':f.start_line,'end_line':f.end_line} for f in targets]}
 manifest['snapshots'][label]={'synthetic_commit':synthetic,'synthetic_tree':tree}
evidence.write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n',encoding='utf-8',newline='\n')
print(json.dumps(manifest,ensure_ascii=False,indent=2))
