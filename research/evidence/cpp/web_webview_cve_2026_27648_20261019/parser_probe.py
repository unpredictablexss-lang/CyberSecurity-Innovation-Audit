import hashlib
import json
import subprocess
from pathlib import Path
from src.parser.ast import parse_source

repo = Path(r'D:\openHarmonyScanner\tmp\chromium-src-cve-2026-27648-audit.git')
path = 'arkweb/ohos_nweb/src/cef_delegate/nweb_handler_delegate.cc'
commits = {
    'vulnerable_parent_6_0': '5ab1905a8fba8d07e9ab4a9453a7787ec274a1a8',
    'fixed_merge_6_0': '4cf313408de7b6d807465ea2bb22e434269b7c5e',
}
results = {}
for label, commit in commits.items():
    blob = subprocess.check_output(['git', '-C', str(repo), 'rev-parse', f'{commit}:{path}'], text=True).strip()
    source = subprocess.check_output(['git', '-C', str(repo), 'show', f'{commit}:{path}'])
    index = parse_source(source.decode('utf-8'), language='cpp')
    results[label] = {
        'commit': commit,
        'blob': blob,
        'bytes': len(source),
        'sha256': hashlib.sha256(source).hexdigest(),
        'parse_status': index.parse_status,
        'parse_issues': index.parse_issues,
        'function_found': any(f.name == 'FlowbufStrAtIndex' for f in index.functions),
    }
out = Path(__file__).with_name('parser-diagnostics.json')
out.write_text(json.dumps(results, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(json.dumps(results, ensure_ascii=False, indent=2))
