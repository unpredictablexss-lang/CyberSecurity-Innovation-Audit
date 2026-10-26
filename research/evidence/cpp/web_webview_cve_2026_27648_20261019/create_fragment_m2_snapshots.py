import hashlib, json, subprocess
from pathlib import Path
from src.parser.ast import parse_source

source_repo = r'D:\openHarmonyScanner\tmp\chromium-src-cve-2026-27648-audit.git'
source_path = 'arkweb/ohos_nweb/src/cef_delegate/nweb_handler_delegate.cc'
commits = {
    'vulnerable': '5ab1905a8fba8d07e9ab4a9453a7787ec274a1a8',
    'fixed': '4cf313408de7b6d807465ea2bb22e434269b7c5e',
}
work_repo = Path(r'D:\openHarmonyScanner\tmp\web-webview-flowbuf-fragment-m2-20261019')
out = Path('research/evidence/cpp/web_webview_cve_2026_27648_20261019/fragment-m2-source-identities.json')
controls = '''#include <vector>
#include <cstddef>
void unguarded(std::vector<int>& items, int index) { items[index] = 1; }
void guarded_loop(std::vector<int>& items) { for (std::size_t index = 0; index < items.size(); ++index) items[index] = 1; }
void unrelated_array(int* items, int index) { if (index >= 0 && index < 4) items[index] = 1; }
void guarded_vector(std::vector<int>& items, int index) { if (index >= 0 && static_cast<std::size_t>(index) < items.size()) items[index] = 1; }
'''
if any(work_repo.iterdir()):
    raise SystemExit(f'refusing non-empty new sample directory: {work_repo}')
work_repo.mkdir(parents=True, exist_ok=True)
subprocess.run(['git','init','-q',str(work_repo)],check=True)
subprocess.run(['git','-C',str(work_repo),'config','user.name','OHScanner Evidence'],check=True)
subprocess.run(['git','-C',str(work_repo),'config','user.email','evidence@example.invalid'],check=True)
manifest = {'basis': 'Exact function ranges extracted from hash-bound upstream source commits; synthetic commits only package these exact bytes for local M2 CLI replay.', 'source_path': source_path, 'snapshots': {}, 'controls_sha256': hashlib.sha256(controls.encode()).hexdigest()}
for label, commit in commits.items():
    raw = subprocess.check_output(['git','-C',source_repo,'show',f'{commit}:{source_path}']).decode('utf-8')
    parsed = parse_source(raw, 'cpp')
    funcs = [f for f in parsed.functions if f.name in {'FlowbufStrAtIndex','ProcessNativeProxyResultNewFlowbuf'}]
    if len(funcs) != 2:
        raise SystemExit(f'{label}: expected 2 functions, found {[(f.name,f.start_line,f.end_line) for f in funcs]}')
    fragment = '\n\n'.join('\n'.join(raw.splitlines()[f.start_line-1:f.end_line]) for f in sorted(funcs,key=lambda f:f.start_line)) + '\n'
    frag_parse = parse_source(fragment, 'cpp')
    if frag_parse.parse_status != 'complete':
        raise SystemExit(f'{label} fragment parse not complete: {frag_parse.parse_status} {frag_parse.parse_issues}')
    (work_repo/'flowbuf_functions.cc').write_text(fragment,encoding='utf-8',newline='\n')
    (work_repo/'vector_controls.cpp').write_text(controls,encoding='utf-8',newline='\n')
    subprocess.run(['git','-C',str(work_repo),'add','flowbuf_functions.cc','vector_controls.cpp'],check=True)
    subprocess.run(['git','-C',str(work_repo),'commit','-qm',label],check=True)
    synthetic = subprocess.check_output(['git','-C',str(work_repo),'rev-parse','HEAD']).decode().strip()
    tree = subprocess.check_output(['git','-C',str(work_repo),'rev-parse','HEAD^{tree}']).decode().strip()
    manifest['snapshots'][label] = {'upstream_commit':commit,'synthetic_snapshot_commit':synthetic,'synthetic_tree':tree,'fragment_sha256':hashlib.sha256(fragment.encode()).hexdigest(),'fragment_bytes':len(fragment.encode()),'function_ranges':[{'name':f.name,'start_line':f.start_line,'end_line':f.end_line} for f in funcs],'fragment_parse_status':frag_parse.parse_status,'fragment_parse_issues':frag_parse.parse_issues,'controls_sha256':manifest['controls_sha256']}
out.write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n',encoding='utf-8',newline='\n')
print(json.dumps(manifest,ensure_ascii=False,indent=2))
