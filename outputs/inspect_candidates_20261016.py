from pathlib import Path
import json, re
root = Path("/mnt/e/网安/CyberSecurity-Innovation-Audit/outputs/reports/community_scan_20261016")
test_re = re.compile(r"(^|/)(test|tests|unittest|unittests|fuzz|mock|sample|example|demo|benchmark)(/|$)")
rows = []
for report_path in sorted(root.glob("*/report.json")):
    report = json.loads(report_path.read_text(encoding="utf-8"))
    repo = report_path.parent.name
    for run in report.get("detector_runs", []):
        for d in run.get("diagnostics", []):
            rows.append({
                "repo": repo,
                "detector": run["tool"],
                "file": d.get("file"),
                "line": d.get("line"),
                "rule": d.get("rule_id"),
                "cwe": d.get("candidate_cwe"),
                "symbol": d.get("symbol"),
                "message": d.get("message"),
                "test_path": bool(test_re.search(d.get("file", ""))),
            })
prod = [r for r in rows if not r["test_path"]]
print("total", len(rows), "prod", len(prod), "test", len(rows)-len(prod))
for key in sorted({(r["repo"], r["detector"], r["rule"]) for r in prod}):
    subset = [r for r in prod if (r["repo"], r["detector"], r["rule"]) == key]
    print("\n", key, len(subset))
    for r in subset[:20]:
        print(f"  {r['file']}:{r['line']} sym={r['symbol']} cwe={r['cwe']}")
        print("   ", r["message"][:500].replace("\n", " "))
