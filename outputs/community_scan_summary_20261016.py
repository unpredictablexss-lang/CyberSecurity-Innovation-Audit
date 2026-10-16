from pathlib import Path
import json, re, collections
root = Path("/mnt/e/网安/CyberSecurity-Innovation-Audit/outputs/reports/community_scan_20261016")
test_re = re.compile(r"(^|/)(test|tests|unittest|unittests|fuzz|mock|sample|example|demo|benchmark)(/|$)")
rows=[]
for p in sorted(root.glob("*/report.json")):
    j=json.loads(p.read_text(encoding="utf-8"))
    repo=p.parent.name
    for run in j.get("detector_runs", []):
        for d in run.get("diagnostics", []):
            if not test_re.search(d.get("file","")):
                rows.append({
                    "repo":repo,"detector":run["tool"],"rule":d.get("rule_id"),
                    "cwe":d.get("candidate_cwe"),"file":d.get("file"),"line":d.get("line"),
                    "symbol":d.get("symbol"),"message":d.get("message")
                })
for repo in sorted({r["repo"] for r in rows}):
    subset=[r for r in rows if r["repo"]==repo]
    print(f"\n### {repo} ({len(subset)})")
    counts=collections.Counter((r["detector"],r["rule"],r["cwe"]) for r in subset)
    for (det,rule,cwe),n in sorted(counts.items()):
        print(f"{n:2d} {det} {rule} {cwe}")
    seen=set()
    for r in subset:
        key=(r["file"],r["line"],r["rule"])
        if key in seen: continue
        seen.add(key)
        print(f"  {r['file']}:{r['line']} {r['rule']} {r['symbol']}")
