import hashlib, json, subprocess
from pathlib import Path
from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.cpp.bounds_detector import CppBoundsDetector
from src.ohscanner.detectors.cpp.integer_bounds_detector import CppIntegerBoundsDetector
from src.ohscanner.fixture import snapshot_digest
from src.parser.ast import parse_source

repo=r'D:\openHarmonyScanner\tmp\chromium-src-cve-2026-27648-audit.git'
source_path='arkweb/ohos_nweb/src/cef_delegate/nweb_handler_delegate.cc'
commits={'vulnerable':'5ab1905a8fba8d07e9ab4a9453a7787ec274a1a8','fixed':'4cf313408de7b6d807465ea2bb22e434269b7c5e'}
target_names={'FlowbufStrAtIndex','ProcessNativeProxyResultNewFlowbuf'}
def unit(path,text,status):return SourceUnit(path,'cpp',text,hashlib.sha256(text.encode()).hexdigest(),status)
def scan(u,detector):
    c=ScanContext(ScanRequest('probe:cve27648','fixture/flowbuf-fragment','3'*40,snapshot_digest((u,)),'current-component:fixture/flowbuf-fragment','fixture-no-build','fixture'),(u,))
    run=detector.detect(c,(u,))
    lines=u.text.splitlines()
    return {'status':run.status,'findings':[{'line':f.line,'source_line':lines[f.line-1].strip() if 0 < f.line <= len(lines) else None,'rule_id':f.rule_id,'symbol':f.symbol,'message':f.message} for f in run.findings]}
results={}
for label,commit in commits.items():
    raw=subprocess.check_output(['git','-C',repo,'show',f'{commit}:{source_path}']).decode()
    full=parse_source(raw,'cpp')
    targets=[f for f in full.functions if f.name in target_names]
    parts='\n\n'.join('\n'.join(raw.splitlines()[f.start_line-1:f.end_line]) for f in sorted(targets,key=lambda f:f.start_line))
    frag=parse_source(parts,'cpp')
    u=unit(f'{label}/flowbuf_functions.cc',parts,frag.parse_status)
    results[label]={'full_parse':full.parse_status,'full_parse_issues':len(full.parse_issues),'function_ranges':[{'name':f.name,'start':f.start_line,'end':f.end_line} for f in targets],'fragment_parse':frag.parse_status,'fragment_issues':frag.parse_issues,'bounds':scan(u,CppBoundsDetector()),'integer_bounds':scan(u,CppIntegerBoundsDetector())}
controls={
 'unguarded_vector':'''#include <vector>\nvoid f(std::vector<int>& v, int index) { v[index] = 1; }''',
 'guarded_vector':'''#include <vector>\nvoid f(std::vector<int>& v, int index) { if (index >= 0 && index < static_cast<int>(v.size())) v[index] = 1; }''',
 'guarded_loop_vector':'''#include <vector>\nvoid f(std::vector<int>& v) { for (size_t index = 0; index < v.size(); ++index) v[index] = 1; }''',
}
for label,text in controls.items():
    parsed=parse_source(text,'cpp'); u=unit(f'control/{label}.cc',text,parsed.parse_status)
    results[label]={'fragment_parse':parsed.parse_status,'bounds':scan(u,CppBoundsDetector()),'integer_bounds':scan(u,CppIntegerBoundsDetector())}
out=Path('research/evidence/cpp/web_webview_cve_2026_27648_20261019/function-fragment-probe.json')
out.write_text(json.dumps(results,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps(results,ensure_ascii=False,indent=2))
