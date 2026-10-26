import hashlib,json,os,subprocess
from pathlib import Path
repo=r'D:\openHarmonyScanner\tmp\chromium-src-cve-2026-27648-audit.git'
outdir=Path(r'D:\openHarmonyScanner\tmp\web-webview-flowbuf-full-tu-m2-20261019')
out=Path('research/evidence/cpp/web_webview_cve_2026_27648_20261019/full-tu-m2-source-identities.json')
env=os.environ.copy(); env['GIT_NO_LAZY_FETCH']='1'
if outdir.exists() and any(outdir.iterdir()): raise SystemExit(f'refusing non-empty directory: {outdir}')
outdir.mkdir(parents=True,exist_ok=True); subprocess.run(['git','init','-q',str(outdir)],check=True)
subprocess.run(['git','-C',str(outdir),'config','user.name','OHScanner Evidence'],check=True); subprocess.run(['git','-C',str(outdir),'config','user.email','evidence@example.invalid'],check=True)
items={'vulnerable':'5ab1905a8fba8d07e9ab4a9453a7787ec274a1a8','fixed':'4cf313408de7b6d807465ea2bb22e434269b7c5e'}
path='arkweb/ohos_nweb/src/cef_delegate/nweb_handler_delegate.cc'; result={'source_path':path,'basis':'Exact full source translation unit bytes copied from locally present pinned upstream blobs; synthetic commits only package the one source file for local M2 CLI without promisor traversal.','snapshots':{}}
for label,commit in items.items():
 raw=subprocess.check_output(['git','-C',repo,'show',f'{commit}:{path}'],env=env,timeout=15)
 (outdir/path).parent.mkdir(parents=True,exist_ok=True); (outdir/path).write_bytes(raw)
 subprocess.run(['git','-C',str(outdir),'add',path],check=True); subprocess.run(['git','-C',str(outdir),'commit','-qm',label],check=True)
 synthetic=subprocess.check_output(['git','-C',str(outdir),'rev-parse','HEAD']).decode().strip(); tree=subprocess.check_output(['git','-C',str(outdir),'rev-parse','HEAD^{tree}']).decode().strip(); blob=subprocess.check_output(['git','-C',repo,'rev-parse',f'{commit}:{path}'],env=env).decode().strip()
 result['snapshots'][label]={'upstream_commit':commit,'upstream_blob':blob,'source_bytes':len(raw),'source_sha256':hashlib.sha256(raw).hexdigest(),'synthetic_commit':synthetic,'synthetic_tree':tree}
out.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8',newline='\n');print(json.dumps(result,ensure_ascii=False,indent=2))
